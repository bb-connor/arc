# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 8 Synthesis

- **Timestamp**: `20261025-031922 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `1527.26s` across 4 parallel passes
- **Total Output**: `165,851` characters (`21,693` words)
- **Claude Max Quota Before Wave 8**: 5-hour `0.0%` | 7-day `89.0%`
- **Claude Max Quota After Wave 8**: 5-hour `9.0%` | 7-day `90.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave8_angle_1_formal_aeneas_and_lean4_deepening_pass_8` | `0` | `success` | `['claude-fable-5-1']` | `none` | `4,740` | `36,269` | `1005.84` |
| `wave8_angle_2_copley_dag_optimization_and_simd_bitset_pass_8` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,807` | `38,862` | `1527.23` |
| `wave8_angle_3_concurrent_loom_and_dst_crash_recovery_pass_8` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,655` | `45,931` | `718.87` |
| `wave8_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_8` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,491` | `44,789` | `768.43` |

---

# Verbatim Treatise - `wave8_angle_1_formal_aeneas_and_lean4_deepening_pass_8`

```rust
    }
}

/// Floor product `(a * b) >> 16`, saturated into the carrier. Total: the widened product has
/// magnitude at most 2^62 and the shift is a constant below the width, so neither `Option` is
/// ever `None`; the fallback arm only documents the sign discipline.
#[inline]
#[must_use]
pub fn q16_sat_mul(a: i32, b: i32) -> i32 {
    let shifted = i64::from(a)
        .checked_mul(i64::from(b))
        .and_then(|w| w.checked_shr(Q16_SHIFT));
    match shifted {
        Some(v) => clamp_i64_to_i32(v),
        None => if (a < 0) ^ (b < 0) { i32::MIN } else { i32::MAX },
    }
}

/// `bps / 10_000` as a Q16.16 fraction, floor. Exactly `Q16_ONE` at a whole share.
#[inline]
#[must_use]
pub fn q16_from_bps(bps: u16) -> i32 {
    let scaled = u32::from(bps)
        .checked_mul(65_536)
        .and_then(|s| s.checked_div(BPS_ONE));
    match scaled {
        Some(v) => i32::try_from(v).unwrap_or(i32::MAX),
        None => 0,
    }
}

/// One Lagrangian term: `acc - lambda * usage`, saturating.
#[inline]
#[must_use]
pub fn q16_penalty_step(acc: i32, lambda: i32, usage: i32) -> i32 {
    q16_sat_sub(acc, q16_sat_mul(lambda, usage))
}

/// Tier-0 penalised score over the five shadow prices (budget, fuel, latency, memory, escrow).
#[must_use]
pub fn q16_penalized_score(
    score: i32,
    lambda: &[i32; SHADOW_PRICES],
    usage: &[i32; SHADOW_PRICES],
) -> i32 {
    lambda
        .iter()
        .zip(usage.iter())
        .fold(score, |acc, (l, u)| q16_penalty_step(acc, *l, *u))
}

/// Closed feasible envelope `[lo, hi]`. The constructor is the only way to obtain a value, so
/// `lo <= hi` holds for every value in existence; `lo` doubles as the fallback `pi_base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Q16Envelope {
    lo: i32,
    hi: i32,
}

impl Q16Envelope {
    #[must_use]
    pub const fn new(lo: i32, hi: i32) -> Option<Self> {
        if lo <= hi { Some(Self { lo, hi }) } else { None }
    }
    #[must_use]
    pub const fn lo(self) -> i32 { self.lo }
    #[must_use]
    pub const fn hi(self) -> i32 { self.hi }
    #[must_use]
    pub const fn fallback(self) -> i32 { self.lo }

    /// `Pi_C(x)`: O(1) shielded projection of an arbitrary predictor output.
    #[must_use]
    pub const fn project(self, score: i32) -> i32 {
        if score < self.lo { self.lo } else if score > self.hi { self.hi } else { score }
    }
}

#[cfg(kani)]
mod kani_fixed {
    use super::*;

    #[kani::proof]
    fn q16_sat_mul_is_floor_then_clamp() {
        let a: i32 = kani::any();
        let b: i32 = kani::any();
        let r = q16_sat_mul(a, b);
        let exact = i64::from(a)
            .checked_mul(i64::from(b))
            .and_then(|w| w.checked_shr(Q16_SHIFT))
            .expect("|a*b| <= 2^62 fits i64");
        if exact > i64::from(i32::MAX) {
            assert_eq!(r, i32::MAX);
        } else if exact < i64::from(i32::MIN) {
            assert_eq!(r, i32::MIN);
        } else {
            assert_eq!(i64::from(r), exact);
        }
        if a >= 0 && b >= 0 { assert!(r >= 0); }
        if (a >= 0 && b <= 0) || (a <= 0 && b >= 0) { assert!(r <= 0); }
    }

    #[kani::proof]
    fn q16_sat_mul_is_monotone_in_the_price() {
        let l1: i32 = kani::any();
        let l2: i32 = kani::any();
        let u: i32 = kani::any();
        kani::assume(l1 <= l2 && u >= 0);
        assert!(q16_sat_mul(l1, u) <= q16_sat_mul(l2, u));
    }

    #[kani::proof]
    fn q16_penalty_step_never_raises_the_score() {
        let acc: i32 = kani::any();
        let lambda: i32 = kani::any();
        let usage: i32 = kani::any();
        kani::assume(lambda >= 0 && usage >= 0);
        assert!(q16_penalty_step(acc, lambda, usage) <= acc);
    }

    #[kani::proof]
    fn q16_from_bps_respects_the_share_cap() {
        let bps: u16 = kani::any();
        let v = q16_from_bps(bps);
        assert!(v >= 0);
        if bps <= 10_000 { assert!(v <= Q16_ONE); }
        if bps == 10_000 { assert_eq!(v, Q16_ONE); }
    }

    /// Envelope preservation: `score` is the learned choice, modelled as pure nondeterminism.
    #[kani::proof]
    fn envelope_projection_is_preserved_for_any_predictor() {
        let lo: i32 = kani::any();
        let hi: i32 = kani::any();
        let score: i32 = kani::any();
        match Q16Envelope::new(lo, hi) {
            None => assert!(lo > hi),
            Some(env) => {
                let v = env.project(score);
                assert!(env.lo() <= v && v <= env.hi());
                assert_eq!(env.project(v), v);
                if lo <= score && score <= hi { assert_eq!(v, score); }
            }
        }
    }
}
```

**Epoch boundaries.** Rollover resets to the grant only when the epoch index advances. Skipped epochs collapse to a single grant, so nothing accrues. A rewound clock leaves the state untouched, so regression can never inflate a budget. The rank function orders the three window codes along the time axis, which lets a harness check that the pinned classifier is monotone in time without assuming its boundary convention.

```rust
//! formal_epoch.rs - Pass 8. Epoch arithmetic and boundary transitions, composed with the pinned
//! `classify_time_window_code` and `budget_commit`. Strictly additive.
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

use crate::formal_aeneas::{budget_commit, BudgetCommitResult};

pub const TIME_WINDOW_VALID: u8 = 0;
pub const TIME_WINDOW_NOT_YET_VALID: u8 = 1;
pub const TIME_WINDOW_EXPIRED: u8 = 2;
pub const TIME_WINDOW_RANK_MALFORMED: u8 = 3;

/// Rank along the time axis: NotYetValid < Valid < Expired; anything else ranks last.
#[inline]
#[must_use]
pub fn time_window_rank(code: u8) -> u8 {
    match code {
        TIME_WINDOW_NOT_YET_VALID => 0,
        TIME_WINDOW_VALID => 1,
        TIME_WINDOW_EXPIRED => 2,
        _ => TIME_WINDOW_RANK_MALFORMED,
    }
}

/// Epoch index of `now`; `None` for a zero epoch length, which callers map to `Deny`.
#[inline]
#[must_use]
pub fn epoch_of(now: u64, epoch_len: u64) -> Option<u64> { now.checked_div(epoch_len) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct EpochGrant { pub invocations: u64, pub units: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct EpochBudget { pub epoch: u64, pub remaining_invocations: u64, pub remaining_units: u64 }

/// Advance: reset to the grant. Same epoch: unchanged. Regression: unchanged.
#[must_use]
pub fn epoch_rollover(state: EpochBudget, grant: EpochGrant, now_epoch: u64) -> (EpochBudget, bool) {
    if now_epoch > state.epoch {
        let next = EpochBudget {
            epoch: now_epoch,
            remaining_invocations: grant.invocations,
            remaining_units: grant.units,
        };
        (next, true)
    } else {
        (state, false)
    }
}

/// Commit inside the current epoch through the pinned `budget_commit`.
#[must_use]
pub fn epoch_commit(state: EpochBudget, invocation_cost: u64, unit_cost: u64) -> (EpochBudget, BudgetCommitResult) {
    let result = budget_commit(state.remaining_invocations, state.remaining_units, invocation_cost, unit_cost);
    let next = EpochBudget {
        epoch: state.epoch,
        remaining_invocations: result.remaining_invocations,
        remaining_units: result.remaining_units,
    };
    (next, result)
}

#[cfg(kani)]
mod kani_epoch {
    use super::*;
    use crate::formal_aeneas::classify_time_window_code;

    #[kani::proof]
    fn time_window_rank_is_monotone_in_now() {
        let n1: u64 = kani::any();
        let n2: u64 = kani::any();
        let issued: u64 = kani::any();
        let expires: u64 = kani::any();
        kani::assume(n1 <= n2);
        let r1 = time_window_rank(classify_time_window_code(n1, issued, expires));
        let r2 = time_window_rank(classify_time_window_code(n2, issued, expires));
        assert!(r1 <= 2 && r2 <= 2);
        assert!(r1 <= r2);
    }

    #[kani::proof]
    fn time_window_interior_and_exterior_are_convention_free() {
        let now: u64 = kani::any();
        let issued: u64 = kani::any();
        let expires: u64 = kani::any();
        kani::assume(issued <= expires);
        let code = classify_time_window_code(now, issued, expires);
        if now < issued { assert_eq!(code, TIME_WINDOW_NOT_YET_VALID); }
        if issued < now && now < expires { assert_eq!(code, TIME_WINDOW_VALID); }
        if now > expires { assert_eq!(code, TIME_WINDOW_EXPIRED); }
    }

    /// CONVENTION PIN: issuance inclusive, expiry exclusive. Fails loudly if the pin moves.
    #[kani::proof]
    fn time_window_boundary_convention_pin() {
        let issued: u64 = kani::any();
        let expires: u64 = kani::any();
        kani::assume(issued < expires);
        assert_eq!(classify_time_window_code(issued, issued, expires), TIME_WINDOW_VALID);
        assert_eq!(classify_time_window_code(expires, issued, expires), TIME_WINDOW_EXPIRED);
    }

    #[kani::proof]
    fn epoch_of_hits_exact_boundaries() {
        let e: u64 = kani::any();
        let len: u64 = kani::any();
        kani::assume(len > 0);
        assert_eq!(epoch_of(e, 0), None);
        if let Some(start) = e.checked_mul(len) {
            assert_eq!(epoch_of(start, len), Some(e));
            if let Some(last_of_prev) = start.checked_sub(1) {
                assert_eq!(epoch_of(last_of_prev, len), e.checked_sub(1));
            }
            if let Some(last) = start.checked_add(len.saturating_sub(1)) {
                assert_eq!(epoch_of(last, len), Some(e));
            }
        }
    }

    #[kani::proof]
    fn epoch_rollover_never_accrues_and_never_rewinds() {
        let state: EpochBudget = kani::any();
        let grant: EpochGrant = kani::any();
        let now_epoch: u64 = kani::any();
        let (next, rolled) = epoch_rollover(state, grant, now_epoch);
        assert!(next.epoch >= state.epoch);
        assert!(next.remaining_units <= state.remaining_units.max(grant.units));
        assert!(next.remaining_invocations <= state.remaining_invocations.max(grant.invocations));
        assert_eq!(rolled, now_epoch > state.epoch);
        if rolled { assert_eq!(next.epoch, now_epoch); } else { assert_eq!(next, state); }
    }

    /// Relies on the two pinned properties of `budget_commit` named in Section 1.
    #[kani::proof]
    fn epoch_commit_conserves_units_within_an_epoch() {
        let state: EpochBudget = kani::any();
        let grant: EpochGrant = kani::any();
        let now_epoch: u64 = kani::any();
        let inv_cost: u64 = kani::any();
        let unit_cost: u64 = kani::any();
        let (after_roll, _) = epoch_rollover(state, grant, now_epoch);
        let (next, result) = epoch_commit(after_roll, inv_cost, unit_cost);
        assert_eq!(next.epoch, after_roll.epoch);
        if result.accepted {
            assert_eq!(next.remaining_units.checked_add(unit_cost), Some(after_roll.remaining_units));
            assert_eq!(next.remaining_invocations.checked_add(inv_cost), Some(after_roll.remaining_invocations));
        } else {
            assert_eq!(next.remaining_units, after_roll.remaining_units);
            assert_eq!(next.remaining_invocations, after_roll.remaining_invocations);
        }
    }
}
```

**Attenuation witnesses.** A hop attenuates its parent when share, expiry, and rights all shrink or stay equal and depth grows by exactly one. That relation is not transitive because of the depth clause, so a second relation, dominance, replaces the depth equality by an inequality. Dominance is reflexive and transitive, every attenuation is a dominance, and so a verified chain's leaf is dominated by its root. The Rust side checks consecutive pairs only. The Lean side proves the chain theorem for every length.

```rust
//! formal_attenuation.rs - Pass 8. Multi-hop delegation attenuation witnesses, fixed capacity,
//! no allocation. Strictly additive.
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

use crate::formal_fixed::{q16_from_bps, q16_sat_mul, Q16_ONE};

pub const MAX_DELEGATION_HOPS: usize = 8;
pub const MAX_SHARE_BPS: u16 = 10_000;
const _: () = assert!(MAX_SHARE_BPS == crate::budget_split::MAX_BUDGET_SHARE_BPS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct DelegationHop {
    pub share_bps: u16,
    pub expires_at: u64,
    pub rights: u64,
    pub depth: u8,
}

const EMPTY_HOP: DelegationHop = DelegationHop { share_bps: 0, expires_at: 0, rights: 0, depth: 0 };

/// `child` carries no right that `parent` lacks.
#[inline]
#[must_use]
pub fn rights_subset(child: u64, parent: u64) -> bool { (child & !parent) == 0 }

/// One hop: the only relation the kernel checks directly.
#[must_use]
pub fn hop_attenuates(parent: DelegationHop, child: DelegationHop) -> bool {
    child.share_bps <= parent.share_bps
        && child.share_bps <= MAX_SHARE_BPS
        && child.expires_at <= parent.expires_at
        && rights_subset(child.rights, parent.rights)
        && parent.depth.checked_add(1) == Some(child.depth)
        && usize::from(child.depth) <= MAX_DELEGATION_HOPS
}

/// Many hops: what the chain theorem delivers about root and leaf.
#[must_use]
pub fn hop_dominates(root: DelegationHop, leaf: DelegationHop) -> bool {
    leaf.share_bps <= root.share_bps
        && leaf.expires_at <= root.expires_at
        && rights_subset(leaf.rights, root.rights)
        && root.depth <= leaf.depth
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttenuationWitness {
    hops: [DelegationHop; MAX_DELEGATION_HOPS],
    len: usize,
}

impl AttenuationWitness {
    #[must_use]
    pub fn from_slice(hops: &[DelegationHop]) -> Option<Self> {
        if hops.len() > MAX_DELEGATION_HOPS { return None; }
        let mut buf = [EMPTY_HOP; MAX_DELEGATION_HOPS];
        for (slot, hop) in buf.iter_mut().zip(hops.iter()) { *slot = *hop; }
        Some(Self { hops: buf, len: hops.len() })
    }

    #[must_use]
    pub fn hops(&self) -> &[DelegationHop] { &self.hops[..self.len] }

    /// Leaf of the chain, or the root itself for the empty witness.
    #[must_use]
    pub fn leaf(&self, root: DelegationHop) -> DelegationHop {
        self.hops().last().copied().unwrap_or(root)
    }

    /// Every consecutive pair attenuates; the empty witness is the root delegating to itself.
    #[must_use]
    pub fn verify(&self, root: DelegationHop) -> bool {
        let mut prev = root;
        for hop in self.hops() {
            if !hop_attenuates(prev, *hop) { return false; }
            prev = *hop;
        }
        true
    }

    /// Effective share of the leaf relative to the root, Q16.16, floor at every hop.
    #[must_use]
    pub fn effective_share_q16(&self) -> i32 {
        self.hops()
            .iter()
            .fold(Q16_ONE, |eff, hop| q16_sat_mul(eff, q16_from_bps(hop.share_bps)))
    }
}

#[cfg(kani)]
mod kani_attenuation {
    use super::*;

    #[kani::proof]
    #[kani::unwind(65)]
    fn rights_subset_is_bit_precise() {
        let c: u64 = kani::any();
        let p: u64 = kani::any();
        let r = rights_subset(c, p);
        assert_eq!(r, (c | p) == p);
        assert_eq!(r, (c & p) == c);
        let mut spec = true;
        for i in 0..64u32 {
            let cb = c.checked_shr(i).map_or(0, |v| v & 1);
            let pb = p.checked_shr(i).map_or(0, |v| v & 1);
            if cb == 1 && pb == 0 { spec = false; }
        }
        assert_eq!(r, spec);
    }

    /// Bounded instance of `Chain.dominates`, `Chain.depth`, and `effShare_le_one`.
    #[kani::proof]
    #[kani::unwind(9)]
    fn verified_witness_dominates_counts_depth_and_stays_within_unit_share() {
        let root: DelegationHop = kani::any();
        let hops: [DelegationHop; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        let witness = AttenuationWitness::from_slice(&hops[..n]).expect("3 <= MAX_DELEGATION_HOPS");
        if witness.verify(root) {
            let leaf = witness.leaf(root);
            assert!(hop_dominates(root, leaf));
            assert_eq!(usize::from(leaf.depth), usize::from(root.depth).checked_add(n).unwrap());
            let eff = witness.effective_share_q16();
            assert!(0 <= eff && eff <= Q16_ONE);
        }
    }
}
```

**Merkle inclusion and committed envelopes.** The inclusion step orients the sibling and compresses one pair. The fold applies it along the path after a depth guard that runs before any hashing. The envelope leaf has a fixed-width injective encoding, and the committed projection returns the fallback unless the leaf is included under the root and well formed. The digest is a trait so the kernel core needs only the shape; the kernel crate supplies the pinned hash.

```rust
//! formal_merkle.rs - Pass 8. Inclusion steps and Merkle-committed Q16.16 envelopes.
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

use crate::formal_fixed::Q16Envelope;

pub const DIGEST_LEN: usize = 32;
pub type Digest = [u8; DIGEST_LEN];
pub const MAX_INCLUSION_DEPTH: usize = 40;

/// Pair compression; implemented in `chio-kernel` with the pinned manifest digest.
pub trait PairDigest {
    fn hash_pair(left: &Digest, right: &Digest) -> Digest;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct InclusionStep { pub sibling: Digest, pub sibling_is_left: bool }

#[inline]
#[must_use]
pub fn inclusion_step<H: PairDigest>(acc: &Digest, step: &InclusionStep) -> Digest {
    if step.sibling_is_left { H::hash_pair(&step.sibling, acc) } else { H::hash_pair(acc, &step.sibling) }
}

/// Left fold of the path; `None` when the path exceeds the depth bound, before any hashing.
#[must_use]
pub fn fold_inclusion_path<H: PairDigest>(leaf: Digest, path: &[InclusionStep]) -> Option<Digest> {
    if path.len() > MAX_INCLUSION_DEPTH { return None; }
    let mut acc = leaf;
    for step in path { acc = inclusion_step::<H>(&acc, step); }
    Some(acc)
}

#[must_use]
pub fn verify_inclusion<H: PairDigest>(leaf: Digest, path: &[InclusionStep], root: &Digest) -> bool {
    matches!(fold_inclusion_path::<H>(leaf, path), Some(acc) if acc == *root)
}

/// Leaf payload committed by the model-card root: one (concept, epoch) envelope cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct EnvelopeLeaf { pub lo: i32, pub hi: i32, pub concept_id: u16, pub model_epoch: u32 }

impl EnvelopeLeaf {
    /// Fixed-width little-endian fields, zero padding. Injective by the round-trip harness.
    #[must_use]
    pub fn encode(self) -> Digest {
        let mut out = [0u8; DIGEST_LEN];
        out[0..4].copy_from_slice(&self.lo.to_le_bytes());
        out[4..8].copy_from_slice(&self.hi.to_le_bytes());
        out[8..10].copy_from_slice(&self.concept_id.to_le_bytes());
        out[10..14].copy_from_slice(&self.model_epoch.to_le_bytes());
        out
    }

    #[must_use]
    pub fn decode(bytes: &Digest) -> Option<Self> {
        let lo = i32::from_le_bytes(<[u8; 4]>::try_from(&bytes[0..4]).ok()?);
        let hi = i32::from_le_bytes(<[u8; 4]>::try_from(&bytes[4..8]).ok()?);
        let concept_id = u16::from_le_bytes(<[u8; 2]>::try_from(&bytes[8..10]).ok()?);
        let model_epoch = u32::from_le_bytes(<[u8; 4]>::try_from(&bytes[10..14]).ok()?);
        if bytes[14..].iter().any(|b| *b != 0) { return None; }
        Some(Self { lo, hi, concept_id, model_epoch })
    }
}

/// `Pi` over a committed envelope. `None` is the `Deny` fallback.
#[must_use]
pub fn shielded_project_committed<H: PairDigest>(
    score: i32,
    leaf: EnvelopeLeaf,
    path: &[InclusionStep],
    root: &Digest,
) -> Option<i32> {
    if !verify_inclusion::<H>(leaf.encode(), path, root) { return None; }
    let envelope = Q16Envelope::new(leaf.lo, leaf.hi)?;
    Some(envelope.project(score))
}

#[cfg(kani)]
mod kani_merkle {
    use super::*;

    /// Structural stand-in. Every property below is parametric in `H`, so any total
    /// implementation discharges it; nothing here needs collision resistance.
    struct ModelDigest;
    impl PairDigest for ModelDigest {
        fn hash_pair(left: &Digest, right: &Digest) -> Digest {
            let mut out = [0u8; DIGEST_LEN];
            for ((o, l), r) in out.iter_mut().zip(left.iter()).zip(right.iter()) {
                *o = l.rotate_left(3) ^ r;
            }
            out
        }
    }

    #[kani::proof]
    fn envelope_leaf_encoding_round_trips() {
        let leaf: EnvelopeLeaf = kani::any();
        assert_eq!(EnvelopeLeaf::decode(&leaf.encode()), Some(leaf));
    }

    #[kani::proof]
    #[kani::unwind(2)]
    fn over_deep_paths_are_rejected_before_hashing() {
        let leaf: Digest = kani::any();
        let steps: [InclusionStep; 41] = kani::any(); // MAX_INCLUSION_DEPTH + 1
        assert_eq!(fold_inclusion_path::<ModelDigest>(leaf, &steps), None);
    }

    /// Bounded instance of `foldPath_append` plus the orientation of `inclusionStep`.
    #[kani::proof]
    #[kani::unwind(34)]
    fn inclusion_step_orients_and_folds_compositionally() {
        let acc: Digest = kani::any();
        let s1: InclusionStep = kani::any();
        let s2: InclusionStep = kani::any();
        let expected = if s1.sibling_is_left {
            ModelDigest::hash_pair(&s1.sibling, &acc)
        } else {
            ModelDigest::hash_pair(&acc, &s1.sibling)
        };
        assert_eq!(inclusion_step::<ModelDigest>(&acc, &s1), expected);
        let whole = fold_inclusion_path::<ModelDigest>(acc, &[s1, s2]);
        let staged = fold_inclusion_path::<ModelDigest>(acc, &[s1])
            .and_then(|mid| fold_inclusion_path::<ModelDigest>(mid, &[s2]));
        assert_eq!(whole, staged);
    }

    /// The Pass 8 theorem, Kani half: `score` is the learned choice.
    #[kani::proof]
    #[kani::unwind(34)]
    fn committed_envelope_projection_is_shielded() {
        let leaf: EnvelopeLeaf = kani::any();
        let step: InclusionStep = kani::any();
        let root: Digest = kani::any();
        let score: i32 = kani::any();
        let path = [step];
        let included = verify_inclusion::<ModelDigest>(leaf.encode(), &path, &root);
        match shielded_project_committed::<ModelDigest>(score, leaf, &path, &root) {
            None => assert!(leaf.lo > leaf.hi || !included),
            Some(v) => {
                assert!(included);
                assert!(leaf.lo <= v && v <= leaf.hi);
            }
        }
    }
}
```

## 3. Lean 4, Creusot, and Apalache mechanization

The Lean file uses only core Lean 4, so it builds inside the existing lake project without new dependencies. Adding one import line to the root module is the only change outside the new file.

```lean
/-
  formal/lean4/Chio/Pass8.lean - Wave 8, Angle 1, Pass 8. Core Lean 4 only. Additive.
-/
namespace Chio.Pass8

namespace Fixed

abbrev one : Nat := 65536

/-- Floor product on the non-negative range: the model of `q16_sat_mul` there. -/
def mulFloor (a f : Nat) : Nat := a * f / one

theorem mulFloor_le_left (a : Nat) {f : Nat} (hf : f ≤ one) : mulFloor a f ≤ a := by
  unfold mulFloor
  calc a * f / one ≤ a * one / one := Nat.div_le_div_right (Nat.mul_le_mul_left a hf)
    _ = a := Nat.mul_div_cancel a (by decide)

theorem mulFloor_mono_left {a b : Nat} (f : Nat) (hab : a ≤ b) :
    mulFloor a f ≤ mulFloor b f := by
  unfold mulFloor
  exact Nat.div_le_div_right (Nat.mul_le_mul_right f hab)

/-- Effective share of a chain: fold of per-hop factors from 1.0. -/
def effShare (shares : List Nat) : Nat := shares.foldl mulFloor one

theorem foldl_mulFloor_le (shares : List Nat) :
    ∀ acc, acc ≤ one → (∀ f, f ∈ shares → f ≤ one) → shares.foldl mulFloor acc ≤ one := by
  induction shares with
  | nil => intro acc hacc _; exact hacc
  | cons f fs ih =>
    intro acc hacc hall
    simp only [List.foldl_cons]
    exact ih (mulFloor acc f)
      (Nat.le_trans (mulFloor_le_left acc (hall f (by simp))) hacc)
      (fun g hg => hall g (by simp [hg]))

theorem effShare_le_one (shares : List Nat) (hall : ∀ f, f ∈ shares → f ≤ one) :
    effShare shares ≤ one :=
  foldl_mulFloor_le shares one (Nat.le_refl one) hall

/-- `Q16Envelope.project` on the integer model. -/
def project (lo hi s : Int) : Int := if s < lo then lo else if hi < s then hi else s

/-- Envelope preservation: `s` is arbitrary, so any predictor is covered. -/
theorem project_mem {lo hi : Int} (s : Int) (h : lo ≤ hi) :
    lo ≤ project lo hi s ∧ project lo hi s ≤ hi := by
  unfold project
  by_cases h1 : s < lo <;> by_cases h2 : hi < s <;> simp [h1, h2] <;> omega

end Fixed

namespace Epoch

/-- NotYetValid < Valid < Expired along the time axis. -/
def rank (now issued expires : Nat) : Nat :=
  if now < issued then 0 else if now < expires then 1 else 2

theorem rank_mono {n₁ n₂ i e : Nat} (h : n₁ ≤ n₂) : rank n₁ i e ≤ rank n₂ i e := by
  unfold rank
  by_cases h1 : n₁ < i <;> by_cases h2 : n₂ < i <;> by_cases h3 : n₁ < e <;>
    by_cases h4 : n₂ < e <;> simp [h1, h2, h3, h4] <;> omega

end Epoch

namespace Attenuation

structure Hop where
  shareBps  : Nat
  expiresAt : Nat
  rights    : Nat
  depth     : Nat

/-- Spec behind `rights_subset`; the bit-precise identity is Kani's half. -/
def SubsetBits (child parent : Nat) : Prop :=
  ∀ i, child.testBit i = true → parent.testBit i = true

theorem SubsetBits.refl (a : Nat) : SubsetBits a a := fun _ h => h

theorem SubsetBits.trans {a b c : Nat} (h₁ : SubsetBits a b) (h₂ : SubsetBits b c) :
    SubsetBits a c := fun i hi => h₂ i (h₁ i hi)

/-- Exactly what `hop_attenuates` checks (minus the two capacity caps). -/
def Attenuates (p c : Hop) : Prop :=
  c.shareBps ≤ p.shareBps ∧ c.expiresAt ≤ p.expiresAt ∧
    SubsetBits c.rights p.rights ∧ c.depth = p.depth + 1

/-- Exactly what `hop_dominates` checks. -/
def Dominates (r l : Hop) : Prop :=
  l.shareBps ≤ r.shareBps ∧ l.expiresAt ≤ r.expiresAt ∧
    SubsetBits l.rights r.rights ∧ r.depth ≤ l.depth

theorem Dominates.refl (h : Hop) : Dominates h h :=
  ⟨Nat.le_refl _, Nat.le_refl _, SubsetBits.refl _, Nat.le_refl _⟩

theorem Dominates.trans {a b c : Hop} (h₁ : Dominates a b) (h₂ : Dominates b c) :
    Dominates a c :=
  ⟨Nat.le_trans h₂.1 h₁.1, Nat.le_trans h₂.2.1 h₁.2.1,
    SubsetBits.trans h₂.2.2.1 h₁.2.2.1, Nat.le_trans h₁.2.2.2 h₂.2.2.2⟩

theorem Attenuates.dominates {p c : Hop} (h : Attenuates p c) : Dominates p c :=
  ⟨h.1, h.2.1, h.2.2.1, by rw [h.2.2.2]; exact Nat.le_succ _⟩

/-- A verified `AttenuationWitness`: consecutive pairs attenuate. -/
inductive Chain : Hop → List Hop → Prop
  | nil  (r : Hop) : Chain r []
  | cons {r c : Hop} {rest : List Hop} (hrc : Attenuates r c) (hc : Chain c rest) :
      Chain r (c :: rest)

def leaf (r : Hop) : List Hop → Hop
  | []        => r
  | c :: rest => leaf c rest

theorem Chain.dominates {r : Hop} {hops : List Hop} (h : Chain r hops) :
    Dominates r (leaf r hops) := by
  induction h with
  | nil r => exact Dominates.refl r
  | cons hrc _ ih =>
    simp only [leaf]
    exact Dominates.trans hrc.dominates ih

theorem Chain.depth {r : Hop} {hops : List Hop} (h : Chain r hops) :
    (leaf r hops).depth = r.depth + hops.length := by
  induction h with
  | nil r => simp [leaf]
  | cons hrc _ ih =>
    simp only [leaf, List.length_cons]
    rw [ih, hrc.2.2.2]
    omega

/-- `MAX_DELEGATION_HOPS` bounds the witness length through the leaf depth. -/
theorem Chain.length_le {r : Hop} {hops : List Hop} {maxDepth : Nat}
    (h : Chain r hops) (hmax : (leaf r hops).depth ≤ maxDepth) :
    hops.length ≤ maxDepth - r.depth := by
  have := h.depth
  omega

end Attenuation

namespace Merkle

variable {α : Type} (H : α → α → α)

def inclusionStep (acc sib : α) (sibIsLeft : Bool) : α :=
  if sibIsLeft then H sib acc else H acc sib

def foldPath : α → List (α × Bool) → α
  | acc, []             => acc
  | acc, (s, b) :: rest => foldPath (inclusionStep H acc s b) rest

theorem foldPath_nil (acc : α) : foldPath H acc [] = acc := rfl

/-- Incremental verification is sound: a path may be folded in stages. -/
theorem foldPath_append (acc : α) (p q : List (α × Bool)) :
    foldPath H acc (p ++ q) = foldPath H (foldPath H acc p) q := by
  induction p generalizing acc with
  | nil => rfl
  | cons hd tl ih =>
    cases hd with
    | mk s b => simp only [List.cons_append, foldPath, ih]

/-- Under pair injectivity, a root and a path determine the leaf. -/
theorem foldPath_injective (hinj : ∀ a b c d, H a b = H c d → a = c ∧ b = d) :
    ∀ (p : List (α × Bool)) (x y : α), foldPath H x p = foldPath H y p → x = y := by
  intro p
  induction p with
  | nil => intro x y h; exact h
  | cons hd tl ih =>
    intro x y h
    cases hd with
    | mk s b =>
      simp only [foldPath] at h
      have h' := ih _ _ h
      cases b with
      | true =>
        have hx : H s x = H s y := by simpa [inclusionStep] using h'
        exact (hinj s x s y hx).2
      | false =>
        have hx : H x s = H y s := by simpa [inclusionStep] using h'
        exact (hinj x s y s hx).1

theorem root_determines_leaf (hinj : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (p : List (α × Bool)) {x y root : α}
    (hx : foldPath H x p = root) (hy : foldPath H y p = root) : x = y :=
  foldPath_injective H hinj p x y (hx.trans hy.symm)

end Merkle

end Chio.Pass8
```

**Creusot contracts.** The contract layer is active only under the `creusot` cfg, so the default build and every existing Why3 session are untouched. Creusot carries the compositional obligations: the projection bounds, the rollover invariants, and the one-hop implication to dominance. The saturating multiply stays with Kani because its proof rests on checked shift and multiply semantics that the pearlite standard library specs may not cover on the current toolchain.

```rust
// formal_fixed.rs / formal_epoch.rs / formal_attenuation.rs - contract mirror.
#[cfg(creusot)]
use creusot_contracts::*;

#[cfg_attr(creusot, requires(self.lo@ <= self.hi@))]
#[cfg_attr(creusot, ensures(self.lo@ <= result@ && result@ <= self.hi@))]
#[cfg_attr(creusot, ensures(self.lo@ <= score@ && score@ <= self.hi@ ==> result@ == score@))]
pub const fn project(self, score: i32) -> i32 { /* body unchanged */ }

#[cfg_attr(creusot, ensures(result.0.epoch@ >= state.epoch@))]
#[cfg_attr(creusot, ensures(result.1 == (now_epoch@ > state.epoch@)))]
#[cfg_attr(creusot, ensures(!result.1 ==> result.0 == state))]
#[cfg_attr(creusot, ensures(result.0.remaining_units@ <= state.remaining_units@
    || result.0.remaining_units@ == grant.units@))]
pub fn epoch_rollover(state: EpochBudget, grant: EpochGrant, now_epoch: u64) -> (EpochBudget, bool)
{ /* body unchanged */ }

#[cfg_attr(creusot, ensures(result ==> hop_dominates(parent, child)))]
#[cfg_attr(creusot, ensures(result ==> child.depth@ == parent.depth@ + 1))]
pub fn hop_attenuates(parent: DelegationHop, child: DelegationHop) -> bool { /* unchanged */ }
```

**Apalache fragment.** The epoch machine models the learned commit choice as an existential over the feasible set, as the Verification Transfer Theorem prescribes. Clock regression is an explicit action so the model checker, not a comment, shows that a rewound clock cannot inflate the budget.

```tla
---------------------------- MODULE Pass8Epoch ----------------------------
EXTENDS Integers
CONSTANTS
  \* @type: Int;
  Grant,
  \* @type: Int;
  MaxEpoch
VARIABLES
  \* @type: Int;
  epoch,
  \* @type: Int;
  nowEpoch,
  \* @type: Int;
  remaining,
  \* @type: Int;
  committed

ConstInit == Grant = 1000 /\ MaxEpoch = 6
Init == epoch = 0 /\ nowEpoch = 0 /\ remaining = Grant /\ committed = 0

Tick     == nowEpoch < MaxEpoch /\ nowEpoch' = nowEpoch + 1
            /\ UNCHANGED <<epoch, remaining, committed>>
Regress  == nowEpoch > 0 /\ nowEpoch' = nowEpoch - 1
            /\ UNCHANGED <<epoch, remaining, committed>>
Rollover == nowEpoch > epoch /\ epoch' = nowEpoch /\ remaining' = Grant
            /\ committed' = 0 /\ UNCHANGED nowEpoch
\* The learned choice: any feasible cost. Nothing is approximated.
Commit   == \E cost \in 0..Grant :
              cost <= remaining /\ remaining' = remaining - cost
              /\ committed' = committed + cost /\ UNCHANGED <<epoch, nowEpoch>>

Next == Tick \/ Regress \/ Rollover \/ Commit

Conservation  == committed + remaining = Grant        \* state invariant
NeverAccrues  == remaining <= Grant                   \* state invariant
EpochMonotone == epoch' >= epoch                      \* action invariant
=============================================================================
```

Every obligation has one discharging engine and, where the property is structural, a second engine covering the unbounded case.

| Obligation | Rust lemma | Kani harness | Lean theorem | Other |
|---|---|---|---|---|
| Floor then clamp, sign discipline | `q16_sat_mul` | `q16_sat_mul_is_floor_then_clamp` | `mulFloor_le_left` | none |
| Penalty monotone in shadow price | `q16_penalty_step` | `q16_sat_mul_is_monotone_in_the_price` | `mulFloor_mono_left` | none |
| Penalty never raises score | `q16_penalized_score` | `q16_penalty_step_never_raises_the_score` | `foldl_mulFloor_le` | none |
| Envelope preservation | `Q16Envelope::project` | `envelope_projection_is_preserved_for_any_predictor` | `project_mem` | Creusot |
| Window rank monotone in time | `time_window_rank` | `time_window_rank_is_monotone_in_now` | `rank_mono` | none |
| Boundary convention | pinned classifier | `time_window_boundary_convention_pin` | none | labelled pin |
| Rollover never accrues or rewinds | `epoch_rollover` | `epoch_rollover_never_accrues_and_never_rewinds` | none | Creusot, Apalache |
| In-epoch conservation | `epoch_commit` | `epoch_commit_conserves_units_within_an_epoch` | none | Apalache |
| Rights subset bit-precise | `rights_subset` | `rights_subset_is_bit_precise` | `SubsetBits.trans` | none |
| Leaf dominated, depth counted | `AttenuationWitness::verify` | `verified_witness_dominates_…` | `Chain.dominates`, `Chain.depth` | Creusot |
| Effective share within unit | `effective_share_q16` | same harness | `effShare_le_one` | none |
| Staged folding sound | `fold_inclusion_path` | `inclusion_step_orients_and_folds_compositionally` | `foldPath_append` | none |
| Root determines leaf | encoding round trip | `envelope_leaf_encoding_round_trips` | `root_determines_leaf` | none |
| Committed projection shielded | `shielded_project_committed` | `committed_envelope_projection_is_shielded` | `project_mem` | none |

The proof manifest gains one entry per row pointing at these names. No existing entry changes, so the existing Lean, Aeneas, Apalache, and Kani proofs are unaffected.

```sh
# Kani, all Pass 8 harnesses (the two 64-bit division harnesses are the slow ones)
cargo kani -p chio-kernel-core --harness kani_fixed --harness kani_epoch \
  --harness kani_attenuation --harness kani_merkle

# Lean, after adding `import Chio.Pass8` to the root module
cd formal/lean4 && lake build Chio.Pass8

# Apalache: state invariants, then the action invariant
apalache-mc check --cinit=ConstInit --init=Init --next=Next \
  --inv=Conservation --length=14 formal/tla/Pass8Epoch.tla
apalache-mc check --cinit=ConstInit --init=Init --next=Next \
  --inv=NeverAccrues --length=14 formal/tla/Pass8Epoch.tla
apalache-mc check --cinit=ConstInit --init=Init --next=Next \
  --inv=EpochMonotone --length=14 formal/tla/Pass8Epoch.tla

# Creusot contract layer
cargo creusot -p chio-kernel-core -- --cfg creusot
```

Pass 8 adds four `#![no_std]` Rust modules with checked arithmetic, sixteen Kani harnesses, a core-only Lean 4 file with eighteen theorems, a Creusot contract mirror, and an Apalache epoch model, all additive to the pinned signatures. The central result is that any predictor output, projected through a Merkle-committed envelope, lands in the envelope or falls back, and under pair injectivity only one envelope can open to a given root along a given path. Two items need your eyes before the run: the two pinned budget commit properties the epoch harness leans on, and the boundary pin harness, which encodes the inclusive-issuance exclusive-expiry convention and should be deleted rather than adjusted if the kernel uses the other one. Nothing was executed in this session, so the commands above are the gate between written and verified.

---

# Verbatim Treatise - `wave8_angle_2_copley_dag_optimization_and_simd_bitset_pass_8`

## 4. Parameters, encoding, and the two invariants the kernel relies on

Fix `P = 537` predicates, `W = 9` plane words (`9·64 = 576 ≥ 537`), `L = 9` literals per clause, `K = MAX_CLAUSES_PER_RULE = 9` clauses per rule, `R = 236` rules, and `RW = 4` rule words. The type the task names, `SymbolicRuleDag<537, 9, 9, 236>`, is `SymbolicRuleDag<P, W, L, R>`; the clause-per-rule bound is a crate constant rather than a type parameter so that the source DAG and the compiled schedule share one capacity story.

A predictor output is a pair of planes. Predicate `j` is `+` when bit `j` of plane `t` is set, `−` when bit `j` of plane `f` is set, and `⊥` otherwise. Two invariants are established by the only public constructor and assumed by every lemma below:

- **I1 (disjointness):** `t[w] & f[w] == 0` for all `w`. Role-asymmetric thresholds with `τ_neg ≤ τ_pos` give this for free, and the constructor enforces it even at `τ_neg = τ_pos`.
- **I2 (padding):** bits at positions `≥ P` are clear in both planes.

Everything the Verification Transfer Theorem needs is that the kernel is proven for *every* pair satisfying I1 and I2. The Kani harness in §9 therefore draws `t` and `f` with `kani::any()` under exactly these two assumptions and nothing else about UltraBERT.

```rust
//! copley_bitset: zero-branch compiled schedules for SymbolicRuleDag<537, 9, 9, 236>.
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub const MAX_CLAUSES_PER_RULE: usize = 9;
pub const FALSE_SLOT: u16 = 0;
pub const VERDICT_ALLOW: u8 = 0;
pub const VERDICT_DENY: u8 = 1;
pub const VERDICT_PENDING: u8 = 2;
pub const VERDICT_DEFER: u8 = 3;

/// 1 iff x != 0. Proof: for x != 0 either x or (2^64 - x) has bit 63 set.
#[inline(always)]
pub const fn nz(x: u64) -> u64 { (x | x.wrapping_neg()).wrapping_shr(63) }
/// all-ones iff a == b.
#[inline(always)]
pub const fn eq_mask(a: u64, b: u64) -> u64 { nz(a ^ b).wrapping_sub(1) }
/// all-ones iff a < b. Precondition: a, b < 2^63 (callers pass values <= 64 * RW).
#[inline(always)]
pub const fn lt_mask(a: u64, b: u64) -> u64 {
    0u64.wrapping_sub(a.wrapping_sub(b).wrapping_shr(63))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct K3Vec<const W: usize> { t: [u64; W], f: [u64; W] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaneError { Overlap { word: usize }, Padding { word: usize } }

/// Validated role-asymmetric thresholds. Shown on the raw `i32` representation;
/// substitute `FixedQ16_16`'s ordering in-tree.
pub struct ThresholdTable<const P: usize> { pos: [i32; P], neg: [i32; P] }

impl<const P: usize> ThresholdTable<P> {
    pub fn new(pos: [i32; P], neg: [i32; P]) -> Result<Self, usize> {
        for j in 0..P { if neg[j] > pos[j] { return Err(j); } }
        Ok(Self { pos, neg })
    }
}

impl<const W: usize> K3Vec<W> {
    pub const BOTTOM: Self = Self { t: [0; W], f: [0; W] };

    /// Offline constructor used by tests and harnesses; checks I1 and I2.
    pub fn from_planes<const P: usize>(t: [u64; W], f: [u64; W]) -> Result<Self, PlaneError> {
        const { assert!(W.saturating_mul(64) >= P) };
        for w in 0..W {
            if t[w] & f[w] != 0 { return Err(PlaneError::Overlap { word: w }); }
            let used = P.saturating_sub(w.saturating_mul(64)).min(64);
            let live = if used == 64 { u64::MAX } else { 1u64.wrapping_shl(used as u32).wrapping_sub(1) };
            if (t[w] | f[w]) & !live != 0 { return Err(PlaneError::Padding { word: w }); }
        }
        Ok(Self { t, f })
    }

    /// Hot-path constructor. Branch-free in the scores; establishes I1 and I2 by construction.
    pub fn from_scores<const P: usize>(tab: &ThresholdTable<P>, score: &[i32; P]) -> Self {
        const { assert!(W.saturating_mul(64) >= P) };
        let mut v = Self::BOTTOM;
        for j in 0..P {
            let hi = u64::from(score[j] >= tab.pos[j]);
            let lo = u64::from(score[j] <= tab.neg[j]) & (hi ^ 1);
            let sh = (j & 63) as u32;
            let w = j.wrapping_shr(6);
            v.t[w] |= hi.wrapping_shl(sh);
            v.f[w] |= lo.wrapping_shl(sh);
        }
        v
    }

    pub fn planes(&self) -> (&[u64; W], &[u64; W]) { (&self.t, &self.f) }
}
```

**Lemma 4.1 (constructor soundness).** `from_scores` returns a vector satisfying I1 and I2. *Proof.* Bit `j` of `t` is `hi`, bit `j` of `f` is `lo & (hi ^ 1)`, so both are never set together. Only indices `j < P` are written. ∎

## 5. Clause canonicalization and topological deduplication

A source clause is a list of up to `L` literals. Its canonical form is the pair of masks `(A, B)`: `A` holds the predicates that appear positively, `B` those that appear negated. Literal order and repetition vanish under this map, which is sound because `∧` in strong Kleene logic is commutative, associative, and idempotent. A clause containing both `x_j` and `¬x_j` is kept as is: in `𝕂₃` it evaluates to `⊥` when `x_j = ⊥`, so it is not constant and must not be folded.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClauseMask<const W: usize> { pub pos: [u64; W], pub neg: [u64; W] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Literal { pub predicate: u16, pub negated: bool }

#[derive(Clone, Copy, Debug)]
pub struct SourceClause<const L: usize> { pub lits: [Literal; L], pub len: u8 }

#[derive(Clone, Copy, Debug)]
pub struct SourceRule<const L: usize> {
    pub rank: u16,
    pub action: u8,
    pub clauses: [SourceClause<L>; MAX_CLAUSES_PER_RULE],
    pub nclauses: u8,
}

pub struct SymbolicRuleDag<const P: usize, const W: usize, const L: usize, const R: usize> {
    pub rules: [SourceRule<L>; R],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileError {
    PredicateOutOfRange { rule: u16, predicate: u16 },
    DuplicateRank { rank: u16 },
    InvalidAction { rule: u16, action: u8 },
    ClauseTableOverflow,
    TooManyRules,
}

fn clause_mask<const P: usize, const W: usize, const L: usize>(
    c: &SourceClause<L>, rule: u16,
) -> Result<ClauseMask<W>, CompileError> {
    let mut m = ClauseMask { pos: [0; W], neg: [0; W] };
    for lit in c.lits.iter().take(usize::from(c.len).min(L)) {
        let p = usize::from(lit.predicate);
        if p >= P {
            return Err(CompileError::PredicateOutOfRange { rule, predicate: lit.predicate });
        }
        let bit = 1u64.wrapping_shl((p & 63) as u32);
        let w = p.wrapping_shr(6);
        if lit.negated { m.neg[w] |= bit; } else { m.pos[w] |= bit; }
    }
    Ok(m)
}

/// Hash-consing into slots 1..=unique. Slot 0 is the FALSE register and is never interned.
fn intern<const W: usize, const U: usize>(
    table: &mut [ClauseMask<W>; U], unique: &mut u16, m: ClauseMask<W>,
) -> Result<u16, CompileError> {
    let n = usize::from(*unique);
    for s in 1..=n {
        if table[s] == m {
            return u16::try_from(s).map_err(|_| CompileError::ClauseTableOverflow);
        }
    }
    let slot = n.checked_add(1).ok_or(CompileError::ClauseTableOverflow)?;
    if slot >= U { return Err(CompileError::ClauseTableOverflow); }
    table[slot] = m;
    *unique = u16::try_from(slot).map_err(|_| CompileError::ClauseTableOverflow)?;
    Ok(*unique)
}
```

The DAG has two levels: clause nodes feed rule nodes. A topological order is therefore any order that emits all clause slots before any rule consumes them; the compiler emits clauses in first-occurrence order, which is also deterministic for a fixed source DAG, so the schedule hash is reproducible.

**Lemma 5.1 (dedup soundness).** If `clause_mask(c₁) = clause_mask(c₂)` then `eval(c₁, x) = eval(c₂, x)` for every `x`. *Proof.* By Lemma 6.1 below, the value of a clause is a function of its masks alone. ∎

**Lemma 5.2 (table bound).** After compiling `R` rules, `unique ≤ R·K`, with equality iff no two source clauses share a canonical form. *Proof.* Each `intern` call appends at most one slot, and there are at most `R·K` calls. ∎

The capacity assertion in §7 is `U ≥ R·K + 1`, the extra slot being the FALSE register. For Copley this is `U = 2125`.

## 6. The zero-branch evaluation kernel

**Definition 6.0 (zero-branch).** A function `evaluate(S, x)` is zero-branch in `x` if the sequence of executed instructions depends only on the schedule `S`. Loop bounds may depend on `S`, including its `unique` field, since `S` is a load-time constant. Bounds checks on indices that come from `S` are allowed under this definition for the same reason; they are never taken, and Kani discharges that in §9.

The kernel computes two word-level accumulators per clause and then two rule-indexed bitsets.

**Lemma 6.1 (mask characterization).** Let `c` have masks `(A, B)` and let `x` satisfy I1. Then
1. `eval(c, x) = +` iff `(A ∧ ¬t) ∨ (B ∧ ¬f) = 0` over all words;
2. `eval(c, x) = −` iff `(A ∧ f) ∨ (B ∧ t) ≠ 0` over some word.

*Proof.* Strong Kleene conjunction is `+` iff every literal is `+`. Literal `x_j` is `+` iff `j ∈ t`, literal `¬x_j` is `+` iff `j ∈ f`. So all literals `+` iff `A ⊆ t` and `B ⊆ f`, which is the word-wise emptiness in (1). The conjunction is `−` iff some literal is `−`: `x_j` is `−` iff `j ∈ f`, `¬x_j` is `−` iff `j ∈ t`, which is (2). The empty clause gives `+`, matching the identity of `∧`. I1 ensures (1) and (2) are exclusive. ∎

**Lemma 6.2 (disjunction and padding).** A rule is `+` iff some clause is `+`, `−` iff all clauses are `−`, `⊥` otherwise. Padding a rule's clause list with the constant `−` clause changes nothing, because `−` is the identity of `∨` in the lattice `− < ⊥ < +`. ∎

```rust
pub struct CompiledSchedule<
    const W: usize, const R: usize, const RW: usize, const U: usize, const UW: usize,
> {
    clauses: [ClauseMask<W>; U],
    unique: u16,
    rules: [[u16; MAX_CLAUSES_PER_RULE]; R],
    act_lo: [u64; RW],
    act_hi: [u64; RW],
    default_code: u8,
}

/// Index of the lowest set bit, or 64 * RW if none. Branch-free.
pub fn ctz_words<const RW: usize>(ws: &[u64; RW]) -> u64 {
    let mut acc = 0u64;
    let mut all_prev_empty = 1u64;
    for w in 0..RW {
        let z = u64::from(ws[w].trailing_zeros());        // 0..=64
        acc = acc.saturating_add(z & 0u64.wrapping_sub(all_prev_empty));
        all_prev_empty &= z.wrapping_shr(6);               // 1 iff z == 64
    }
    acc
}

fn select_word<const RW: usize>(ws: &[u64; RW], wi: u64) -> u64 {
    let mut out = 0u64;
    for (w, &word) in ws.iter().enumerate() {
        out |= word & eq_mask(w as u64, wi);
    }
    out
}

impl<const W: usize, const R: usize, const RW: usize, const U: usize, const UW: usize>
    CompiledSchedule<W, R, RW, U, UW>
{
    pub const EMPTY: Self = Self {
        clauses: [ClauseMask { pos: [0; W], neg: [0; W] }; U],
        unique: 0,
        rules: [[FALSE_SLOT; MAX_CLAUSES_PER_RULE]; R],
        act_lo: [0; RW],
        act_hi: [0; RW],
        default_code: VERDICT_ALLOW,
    };

    pub fn unique_clauses(&self) -> u16 { self.unique }

    /// Exact instruction count of `evaluate` under the cost model of §8.
    pub const fn wcet_instructions(unique: usize) -> usize {
        let per_clause = W.saturating_mul(8).saturating_add(11);
        let per_rule = MAX_CLAUSES_PER_RULE.saturating_mul(6).saturating_add(6);
        W.saturating_mul(2)
            .saturating_add(unique.saturating_mul(per_clause))
            .saturating_add(R.saturating_mul(per_rule))
            .saturating_add(RW.saturating_mul(26))
            .saturating_add(22)
    }

    #[allow(clippy::cast_possible_truncation)] // final value is masked to two bits
    pub fn evaluate(&self, x: &K3Vec<W>) -> u8 {
        // Phase 0: complement planes once.                               2W ops
        let mut nt = [0u64; W];
        let mut nf = [0u64; W];
        for w in 0..W { nt[w] = !x.t[w]; nf[w] = !x.f[w]; }

        // Phase 1: clause results as two bit planes; slot 0 is `-`.      U(8W+11) ops
        let mut ct = [0u64; UW];
        let mut cf = [0u64; UW];
        cf[0] = 1;
        let unique = usize::from(self.unique);
        for s in 1..=unique {
            let c = &self.clauses[s];
            let mut miss = 0u64;
            let mut hit = 0u64;
            for w in 0..W {
                miss |= (c.pos[w] & nt[w]) | (c.neg[w] & nf[w]);
                hit |= (c.pos[w] & x.f[w]) | (c.neg[w] & x.t[w]);
            }
            let is_t = nz(miss) ^ 1;
            let is_f = nz(hit);
            let sh = (s & 63) as u32;
            let wi = s.wrapping_shr(6);
            ct[wi] |= is_t.wrapping_shl(sh);
            cf[wi] |= is_f.wrapping_shl(sh);
        }

        // Phase 2: rules in rank order; bit r of `fire` / `unk`.          R(6K+6) ops
        let mut fire = [0u64; RW];
        let mut unk = [0u64; RW];
        for r in 0..R {
            let mut any_t = 0u64;
            let mut all_f = 1u64;
            for &slot in &self.rules[r] {
                let s = usize::from(slot);
                let sh = (s & 63) as u32;
                let wi = s.wrapping_shr(6);
                any_t |= ct[wi].wrapping_shr(sh) & 1;
                all_f &= cf[wi].wrapping_shr(sh) & 1;
            }
            let is_unk = (any_t | all_f) ^ 1;
            let sh = (r & 63) as u32;
            let wi = r.wrapping_shr(6);
            fire[wi] |= any_t.wrapping_shl(sh);
            unk[wi] |= is_unk.wrapping_shl(sh);
        }

        // Phase 3: branch-free short circuit.                             26RW + 22 ops
        let ff = ctz_words(&fire);
        let fu = ctz_words(&unk);
        let has_fire = lt_mask(ff, R as u64);
        let defer = lt_mask(fu, ff);
        let wi = ff.wrapping_shr(6);
        let sh = (ff & 63) as u32;
        let lo = select_word(&self.act_lo, wi).wrapping_shr(sh) & 1;
        let hi = select_word(&self.act_hi, wi).wrapping_shr(sh) & 1;
        let chosen = (lo | hi.wrapping_shl(1)) & has_fire;
        let dflt = u64::from(self.default_code) & !has_fire;
        let code = chosen | dflt;
        let verdict = (code & !defer) | (u64::from(VERDICT_DEFER) & defer);
        (verdict & 3) as u8
    }
}
```

**Lemma 6.3 (multiword count-trailing-zeros).** `ctz_words(ws)` equals the least index of a set bit, or `64·RW` if none. *Proof.* Let `i` be the first word with a set bit and `z_i` its trailing-zero count. For `w < i`, `z_w = 64`, so `all_prev_empty` stays 1 and each adds 64. At `w = i` it adds `z_i` and `all_prev_empty` becomes 0, after which the mask zeroes every addend. The total `64·i + z_i` is at most `64·RW < 2^63`, so saturation is unreachable and the `lt_mask` precondition holds downstream. ∎

**Theorem 6.4 (trace independence).** `evaluate` is zero-branch in `x` in the sense of Definition 6.0. *Proof.* By inspection of the three phases: every loop bound is `W`, `UW`, `R`, `RW`, `K`, or `self.unique`; every index is a loop counter or a field of `self`; every operation applied to a value derived from `x` is a bitwise operation, a constant shift, `trailing_zeros`, or `saturating_add`, none of which has data-dependent control flow. The `bool` to `u64` conversions of §4 live in the constructor and compile to set-on-condition, but they are outside this function in any case. ∎

## 7. Short-circuit rank ordering and the equivalence theorem

The HushSpec IR semantics is sequential. Rules are scanned in rank order; a `−` rule is skipped; the first `+` rule returns its action; a `⊥` rule encountered before any `+` rule returns `Defer`, because its true value might be `+` and change the outcome. `Defer` is the conservative fallback `⊥_x` demanded by Law 2. The compiler realizes the scan without a branch by placing rules at bit positions equal to their rank, so that `ctz` is the short circuit.

```rust
/// Stable ordering of rule indices by rank; ranks must be unique for determinism.
pub fn rank_order<const P: usize, const W: usize, const L: usize, const R: usize>(
    dag: &SymbolicRuleDag<P, W, L, R>,
) -> Result<[u16; R], CompileError> {
    let mut order = [0u16; R];
    for i in 0..R { order[i] = u16::try_from(i).map_err(|_| CompileError::TooManyRules)?; }
    for i in 1..R {
        let mut j = i;
        while j > 0
            && dag.rules[usize::from(order[j.wrapping_sub(1)])].rank
                > dag.rules[usize::from(order[j])].rank
        {
            order.swap(j, j.wrapping_sub(1));
            j = j.wrapping_sub(1);
        }
    }
    for i in 1..R {
        let a = dag.rules[usize::from(order[i.wrapping_sub(1)])].rank;
        if a == dag.rules[usize::from(order[i])].rank {
            return Err(CompileError::DuplicateRank { rank: a });
        }
    }
    Ok(order)
}

/// Offline compiler. `out` is caller-provided so the 300 KB table never lives on a kernel stack.
pub fn compile_into<
    const P: usize, const W: usize, const L: usize, const R: usize,
    const RW: usize, const U: usize, const UW: usize,
>(
    dag: &SymbolicRuleDag<P, W, L, R>,
    default_code: u8,
    out: &mut CompiledSchedule<W, R, RW, U, UW>,
) -> Result<(), CompileError> {
    const { assert!(W.saturating_mul(64) >= P) };
    const { assert!(RW.saturating_mul(64) >= R) };
    const { assert!(U >= R.saturating_mul(MAX_CLAUSES_PER_RULE).saturating_add(1)) };
    const { assert!(UW.saturating_mul(64) >= U) };
    if default_code > VERDICT_PENDING {
        return Err(CompileError::InvalidAction { rule: u16::MAX, action: default_code });
    }
    let order = rank_order(dag)?;
    *out = CompiledSchedule::EMPTY;
    out.default_code = default_code;
    for (r, &src) in order.iter().enumerate() {
        let rule = &dag.rules[usize::from(src)];
        if rule.action > VERDICT_PENDING {
            return Err(CompileError::InvalidAction { rule: src, action: rule.action });
        }
        let n = usize::from(rule.nclauses).min(MAX_CLAUSES_PER_RULE);
        for (k, c) in rule.clauses.iter().take(n).enumerate() {
            let m = clause_mask::<P, W, L>(c, src)?;
            out.rules[r][k] = intern(&mut out.clauses, &mut out.unique, m)?;
        }
        let sh = (r & 63) as u32;
        let wi = r.wrapping_shr(6);
        out.act_lo[wi] |= u64::from(rule.action & 1).wrapping_shl(sh);
        out.act_hi[wi] |= u64::from(rule.action.wrapping_shr(1) & 1).wrapping_shl(sh);
    }
    Ok(())
}

pub type CopleyDag = SymbolicRuleDag<537, 9, 9, 236>;
pub type CopleySchedule = CompiledSchedule<9, 236, 4, 2125, 34>;
```

The branching reference, used by the Kani harness and the differential tests:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum K3 { Pos, Neg, Bot }

impl<const W: usize> K3Vec<W> {
    pub fn get(&self, j: usize) -> K3 {
        let w = j.wrapping_shr(6);
        let b = (j & 63) as u32;
        match (self.t[w].wrapping_shr(b) & 1, self.f[w].wrapping_shr(b) & 1) {
            (1, _) => K3::Pos,
            (_, 1) => K3::Neg,
            _ => K3::Bot,
        }
    }
}

const fn k3_not(a: K3) -> K3 { match a { K3::Pos => K3::Neg, K3::Neg => K3::Pos, K3::Bot => K3::Bot } }
const fn k3_and(a: K3, b: K3) -> K3 {
    match (a, b) { (K3::Neg, _) | (_, K3::Neg) => K3::Neg, (K3::Pos, K3::Pos) => K3::Pos, _ => K3::Bot }
}
const fn k3_or(a: K3, b: K3) -> K3 {
    match (a, b) { (K3::Pos, _) | (_, K3::Pos) => K3::Pos, (K3::Neg, K3::Neg) => K3::Neg, _ => K3::Bot }
}

pub fn rule_value<const L: usize, const W: usize>(rule: &SourceRule<L>, x: &K3Vec<W>) -> K3 {
    let mut acc = K3::Neg;
    for c in rule.clauses.iter().take(usize::from(rule.nclauses).min(MAX_CLAUSES_PER_RULE)) {
        let mut cv = K3::Pos;
        for lit in c.lits.iter().take(usize::from(c.len).min(L)) {
            let v = x.get(usize::from(lit.predicate));
            cv = k3_and(cv, if lit.negated { k3_not(v) } else { v });
        }
        acc = k3_or(acc, cv);
    }
    acc
}

/// HushSpec sequential semantics over an already rank-ordered index list.
pub fn seq_verdict<const P: usize, const W: usize, const L: usize, const R: usize>(
    dag: &SymbolicRuleDag<P, W, L, R>, order: &[u16; R], x: &K3Vec<W>, default_code: u8,
) -> u8 {
    for &i in order {
        match rule_value(&dag.rules[usize::from(i)], x) {
            K3::Neg => continue,
            K3::Pos => return dag.rules[usize::from(i)].action,
            K3::Bot => return VERDICT_DEFER,
        }
    }
    default_code
}
```

**Theorem 7.1 (short-circuit equivalence).** For every schedule produced by `compile_into` from `dag` with order `order`, and every `x` satisfying I1 and I2, `evaluate(x) = seq_verdict(dag, order, x, default)`.

*Proof.* Let `v_r` be the `𝕂₃` value of the rule at rank position `r`. By Lemmas 6.1 and 6.2, bit `r` of `fire` is set iff `v_r = +` and bit `r` of `unk` is set iff `v_r = ⊥`. By Lemma 6.3, `ff = min{r : v_r = +}` and `fu = min{r : v_r = ⊥}`, each defaulting to `64·RW ≥ R` when empty. The sequential scan halts at position `m = min(ff, fu)`, and `ff ≠ fu` whenever both are below `R` because a rule has one value. Three cases:

- `fu < ff`: the scan meets a `⊥` first and returns `Defer`. In the kernel `defer` is all-ones, so `verdict = VERDICT_DEFER`.
- `ff < fu` and `ff < R`: the scan returns the action of rank `ff`. In the kernel `defer = 0`, `has_fire` is all-ones, and the two selected bits reconstruct `action` because `compile_into` wrote exactly its low and high bit at position `ff`. The `dflt` term is masked out.
- `ff = fu = 64·RW`: no rule is `+` or `⊥`, the scan falls through to `default`. In the kernel `defer = 0`, `has_fire = 0`, so `code = default_code`.

The cases are exhaustive, so the two functions agree. ∎

This theorem is what lets Tier-1 userland use the branching `seq_verdict` for average-case speed while the `#![no_std]` kernel path uses `evaluate`; both are the same function extensionally, and the Kani harness checks the claim on the Rust code rather than on a model of it.

## 8. Exact worst-case instruction count

**Cost model.** One unit for each 64-bit ALU operation applied to a value: `& | ^ !`, shifts, `wrapping_neg`, `wrapping_sub`, `saturating_add`, `trailing_zeros`, and the implicit mask-and-OR into an accumulator. Loads, stores, and address arithmetic on loop counters are free. This is the same model `formal_core` uses for `budget_commit` and keeps the count architecture-neutral.

**Theorem 8.1 (exact count).** With `U` the number of interned clauses, `evaluate` executes exactly

`N(U) = 2W + U·(8W + 11) + R·(6K + 6) + 26·RW + 22`

operations, independent of `x`.

*Proof.* Phase 0 performs two complements per word. In Phase 1, each clause performs per word two ANDs and one OR into each of `miss` and `hit`, giving 8W, then `nz(miss)` costs 3 and the `^ 1` costs 1, `nz(hit)` costs 3, and the two shifted ORs into the bit planes cost 4, totalling `8W + 11`. In Phase 2 each of the `K` clause references costs a shift, a mask, and an accumulate for each plane, giving `6K`; `is_unk` costs 2 and the two shifted ORs cost 4. In Phase 3 each `ctz_words` costs `6·RW`; the two `lt_mask` calls cost 3 each; `wi` and `sh` cost 1 each; each `select_word` costs `7·RW` plus a shift and a mask; `chosen` costs 3, `dflt` costs 2, `code` costs 1, and the final blend costs 4. Summing the Phase 3 constants gives `26·RW + 22`. Independence from `x` is Theorem 6.4. ∎

For Copley, `N(U) = 83·U + 14,304`.

| Interned clauses `U` | `N(U)` operations | Scalar time at 3 GHz, 1 op/cycle |
|---|---|---|
| 2,124 (no sharing, Lemma 5.2 bound) | 190,596 | ≈ 64 µs |
| 1,062 | 102,450 | ≈ 34 µs |
| 531 | 58,377 | ≈ 19 µs |

The worst case sits inside Tier-1's 0.5 ms floor with an order of magnitude to spare and is not a Tier-0 workload; the Tier-0 micro-models remain the six `FixedQ16_16` predictors. The compiler writes `unique` and `N(unique)` into the receipt under the existing `model_metadata` key as `model_metadata.copley_schedule = { unique_clauses, wcet_instructions, schedule_hash }`. This is strictly additive: `RESERVED_RECEIPT_METADATA_KEYS` keeps its length of 35.

```lean
namespace Copley.Schedule

inductive K3 where | pos | neg | bot
  deriving DecidableEq, Repr

namespace K3
def and : K3 → K3 → K3
  | .neg, _ | _, .neg => .neg
  | .pos, .pos => .pos
  | _, _ => .bot
def or : K3 → K3 → K3
  | .pos, _ | _, .pos => .pos
  | .neg, .neg => .neg
  | _, _ => .bot
def not : K3 → K3 | .pos => .neg | .neg => .pos | .bot => .bot
end K3

/-- A predictor output satisfying I1. -/
structure Assign where
  t : Nat → Bool
  f : Nat → Bool
  disj : ∀ j, ¬ (t j = true ∧ f j = true)

def Assign.val (x : Assign) (j : Nat) : K3 :=
  if x.t j then .pos else if x.f j then .neg else .bot

structure Lit where
  pred : Nat
  negated : Bool

def Lit.eval (x : Assign) (l : Lit) : K3 :=
  if l.negated then (x.val l.pred).not else x.val l.pred

def Clause.eval (x : Assign) (c : List Lit) : K3 :=
  c.foldr (fun l acc => (l.eval x).and acc) .pos

def Rule.eval (x : Assign) (r : List (List Lit)) : K3 :=
  r.foldr (fun c acc => (Clause.eval x c).or acc) .neg

/-- The `miss` and `hit` accumulators of the Rust kernel, as propositions. -/
def miss (x : Assign) (c : List Lit) : Prop :=
  ∃ l ∈ c, (l.negated = false ∧ x.t l.pred = false) ∨ (l.negated = true ∧ x.f l.pred = false)
def hit (x : Assign) (c : List Lit) : Prop :=
  ∃ l ∈ c, (l.negated = false ∧ x.f l.pred = true) ∨ (l.negated = true ∧ x.t l.pred = true)

theorem clause_pos_iff (x : Assign) (c : List Lit) :
    Clause.eval x c = .pos ↔ ¬ miss x c := by
  induction c with
  | nil => simp [Clause.eval, miss]
  | cons l rest ih =>
    simp only [Clause.eval, List.foldr, miss, List.mem_cons, exists_eq_or_imp]
    cases hl : l.negated <;> cases ht : x.t l.pred <;> cases hf : x.f l.pred <;>
      simp_all [Lit.eval, Assign.val, K3.and, K3.not, Clause.eval, miss] <;>
      first | exact absurd ⟨ht, hf⟩ (x.disj l.pred) | constructor <;> intro h <;> simp_all

theorem clause_neg_iff (x : Assign) (c : List Lit) :
    Clause.eval x c = .neg ↔ hit x c := by
  induction c with
  | nil => simp [Clause.eval, hit]
  | cons l rest ih =>
    simp only [Clause.eval, List.foldr, hit, List.mem_cons, exists_eq_or_imp]
    cases hl : l.negated <;> cases ht : x.t l.pred <;> cases hf : x.f l.pred <;>
      simp_all [Lit.eval, Assign.val, K3.and, K3.not, Clause.eval, hit] <;>
      first | exact absurd ⟨ht, hf⟩ (x.disj l.pred) | constructor <;> intro h <;> simp_all

inductive Verdict where | code (a : Nat) | defer
  deriving DecidableEq

def seqVerdict (x : Assign) (d : Nat) : List (List (List Lit) × Nat) → Verdict
  | [] => .code d
  | (r, a) :: rest =>
    match Rule.eval x r with
    | .pos => .code a
    | .bot => .defer
    | .neg => seqVerdict x d rest

def firstIdx (p : K3 → Bool) (x : Assign) (rs : List (List (List Lit) × Nat)) : Option Nat :=
  (rs.enum.find? (fun e => p (Rule.eval x e.2.1))).map (·.1)

def parVerdict (x : Assign) (d : Nat) (rs : List (List (List Lit) × Nat)) : Verdict :=
  match firstIdx (· == .pos) x rs, firstIdx (· == .bot) x rs with
  | some ff, some fu => if fu < ff then .defer else .code (rs.getD ff ([], d)).2
  | some ff, none => .code (rs.getD ff ([], d)).2
  | none, some _ => .defer
  | none, none => .code d

/-- Theorem 7.1 at the IR level: induction on `rs`; the head's value decides which
    branch of `firstIdx` is `some 0`, and the tail shifts every index by one. -/
theorem par_eq_seq (x : Assign) (d : Nat) (rs : List (List (List Lit) × Nat)) :
    parVerdict x d rs = seqVerdict x d rs := by
  induction rs with
  | nil => rfl
  | cons hd tl ih =>
    rcases hd with ⟨r, a⟩
    cases hv : Rule.eval x r <;>
      simp [parVerdict, seqVerdict, firstIdx, List.enum_cons, List.find?, hv] at ih ⊢ <;>
      (try exact ih) <;>
      simp_all [parVerdict, firstIdx, Option.map, List.enum_eq_zip_range]

/-- Theorem 8.1 as a closed form. -/
def evalCost (W K U R RW : Nat) : Nat :=
  2 * W + U * (8 * W + 11) + R * (6 * K + 6) + 26 * RW + 22

theorem copley_wcet : evalCost 9 9 2124 236 4 = 190596 := by
  norm_num [evalCost]

theorem cost_mono {W K U₁ U₂ R RW : Nat} (h : U₁ ≤ U₂) :
    evalCost W K U₁ R RW ≤ evalCost W K U₂ R RW := by
  unfold evalCost
  have := Nat.mul_le_mul_right (8 * W + 11) h
  linarith

end Copley.Schedule
```

The Aeneas extraction of `evaluate` is a cost-instrumented term because every arithmetic step is a named `wrapping_*`, `saturating_*`, or bitwise call; the Lean side counts calls per phase with the same constants as Theorem 8.1. The `par_eq_seq` proof is by induction with a three-way case split on the head rule's value and is discharged by `simp` plus the enumerated-index shift lemma, as sketched above; the two clause lemmas are the bridge from the extracted word operations to `Rule.eval`.

## 9. Kani harness and differential equivalence against HushSpec IR

Kani runs on a small instantiation so that bounded model checking is exhaustive. `W = 1`, `RW = 1`, and `UW = 1` still exercise every mask, shift, select, and sentinel path, including the `ff = 64·RW` case.

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    const P: usize = 12;
    const W: usize = 1;
    const L: usize = 3;
    const R: usize = 3;
    const RW: usize = 1;
    const U: usize = R.saturating_mul(MAX_CLAUSES_PER_RULE).saturating_add(1); // 28
    const UW: usize = 1;

    fn any_k3() -> K3Vec<W> {
        let t: u64 = kani::any();
        let f: u64 = kani::any();
        kani::assume(t & f == 0);
        kani::assume((t | f).wrapping_shr(P as u32) == 0);
        match K3Vec::<W>::from_planes::<P>([t], [f]) {
            Ok(v) => v,
            Err(_) => kani::assume(false) /* unreachable under the assumptions */,
        }
    }

    fn any_dag() -> SymbolicRuleDag<P, W, L, R> {
        let lit = || Literal { predicate: kani::any(), negated: kani::any() };
        let clause = || SourceClause::<L> { lits: [lit(), lit(), lit()], len: kani::any() };
        let rule = || SourceRule::<L> {
            rank: kani::any(), action: kani::any(),
            clauses: [clause(), clause(), clause(), clause(), clause(), clause(), clause(), clause(), clause()],
            nclauses: kani::any(),
        };
        SymbolicRuleDag { rules: [rule(), rule(), rule()] }
    }

    static mut SCRATCH: CompiledSchedule<W, R, RW, U, UW> = CompiledSchedule::EMPTY;

    #[kani::proof]
    #[kani::unwind(64)]
    fn evaluate_matches_seq_verdict_and_never_panics() {
        let dag = any_dag();
        let default: u8 = kani::any();
        let mut sched = CompiledSchedule::<W, R, RW, U, UW>::EMPTY;
        if compile_into(&dag, default, &mut sched).is_err() { return; }
        let order = rank_order(&dag).expect("compile succeeded, so ranks are unique");
        let x = any_k3();
        assert_eq!(sched.evaluate(&x), seq_verdict(&dag, &order, &x, default));
        assert!(sched.evaluate(&x) <= VERDICT_DEFER);
    }

    #[kani::proof]
    fn primitives_are_exact() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        assert_eq!(nz(a), u64::from(a != 0));
        assert_eq!(eq_mask(a, b), if a == b { u64::MAX } else { 0 });
        kani::assume(a < (1u64 << 63) && b < (1u64 << 63));
        assert_eq!(lt_mask(a, b), if a < b { u64::MAX } else { 0 });
        let ws: [u64; 2] = kani::any();
        let expect = (0..128u64).find(|i| ws[(*i >> 6) as usize] >> (*i & 63) & 1 == 1).unwrap_or(128);
        assert_eq!(ctz_words(&ws), expect);
    }
}
```

The first harness is the Verification Transfer Theorem in executable form. The predictor is `kani::any()`, the compiled schedule is nondeterministic, and the only facts about `x` are I1 and I2. The absence of a panic in `evaluate` is checked at the same time, which certifies that no bounds check inside the kernel is ever taken for a schedule the compiler accepted.

The differential suite runs against the production IR. It assumes exactly three names from `chio-policy`: the IR type `HushSpecIr`, its sequential evaluator `HushSpecEvaluator`, and the three-valued assignment type `K3Assignment` that the evaluator already consumes. Those names are the adapter boundary and must be matched to the crate's actual exports when the test is landed; nothing else about `chio-policy` is assumed.

```rust
#[cfg(test)]
mod differential {
    use super::*;
    use chio_policy::hushspec::{HushSpecEvaluator, HushSpecIr, K3Assignment};
    use proptest::prelude::*;

    /// Lowers HushSpec IR to the source DAG. Returns Err if the IR exceeds Copley's bounds.
    fn lower(ir: &HushSpecIr) -> Result<CopleyDag, CompileError> {
        let mut rules = [SourceRule::<9> {
            rank: 0, action: VERDICT_ALLOW,
            clauses: [SourceClause { lits: [Literal { predicate: 0, negated: false }; 9], len: 0 }; 9],
            nclauses: 0,
        }; 236];
        for (i, rule) in ir.rules().iter().enumerate().take(236) {
            rules[i].rank = rule.rank();
            rules[i].action = rule.action().code();
            for (k, clause) in rule.clauses().iter().enumerate().take(9) {
                for (n, lit) in clause.literals().iter().enumerate().take(9) {
                    rules[i].clauses[k].lits[n] = Literal { predicate: lit.predicate_id(), negated: lit.is_negated() };
                }
                rules[i].clauses[k].len = clause.literals().len().min(9) as u8;
            }
            rules[i].nclauses = rule.clauses().len().min(9) as u8;
        }
        Ok(CopleyDag { rules })
    }

    fn planes(x: &K3Assignment) -> K3Vec<9> {
        let mut t = [0u64; 9];
        let mut f = [0u64; 9];
        for j in 0..537 {
            match x.value(j) {
                K3::Pos => t[j >> 6] |= 1 << (j & 63),
                K3::Neg => f[j >> 6] |= 1 << (j & 63),
                K3::Bot => {}
            }
        }
        K3Vec::from_planes::<537>(t, f).expect("assignment is three-valued, so planes are disjoint")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20_000))]
        #[test]
        fn schedule_matches_hushspec(ir in HushSpecIr::arbitrary_bounded(236, 9, 9, 537),
                                     x in K3Assignment::arbitrary(537)) {
            let dag = lower(&ir)?;
            let mut sched = alloc::boxed::Box::new(CopleySchedule::EMPTY);
            compile_into(&dag, VERDICT_ALLOW, &mut sched)?;
            let expected = HushSpecEvaluator::new(&ir).verdict(&x).code();
            prop_assert_eq!(sched.evaluate(&planes(&x)), expected);
            prop_assert_eq!(
                CopleySchedule::wcet_instructions(usize::from(sched.unique_clauses())),
                83 * usize::from(sched.unique_clauses()) + 14_304
            );
        }
    }
}
```

The second assertion ties the Rust `wcet_instructions` constant to the Lean `evalCost` closed form for the deployed parameters, so a change to either side fails the test rather than silently diverging.

Apalache checks the same equivalence as a state machine, with the rule values as a bounded constant and the sequential scan as the only transition. Its invariant says the final output of the scan is the closed form the kernel computes.

```tla
---------------------------- MODULE CopleyScanEquivalence ----------------------------
EXTENDS Integers, Sequences
CONSTANTS R, Vals, Act, Default
\* @type: Int;                 R
\* @type: Int -> Str;          Vals   \in [1..R -> {"pos","neg","bot"}]
\* @type: Int -> Str;          Act
\* @type: Str;                 Default
VARIABLES pc, out

Init == pc = 1 /\ out = "none"

Step ==
  /\ pc <= R /\ out = "none"
  /\ CASE Vals[pc] = "neg" -> pc' = pc + 1 /\ UNCHANGED out
       [] Vals[pc] = "pos" -> out' = Act[pc] /\ UNCHANGED pc
       [] OTHER            -> out' = "defer" /\ UNCHANGED pc

Finish == pc = R + 1 /\ out = "none" /\ out' = Default /\ UNCHANGED pc
Next == Step \/ Finish

First(v) == IF \E i \in 1..R : Vals[i] = v
            THEN CHOOSE i \in 1..R : Vals[i] = v /\ \A j \in 1..(i-1) : Vals[j] # v
            ELSE R + 1

Par == IF First("bot") < First("pos") THEN "defer"
       ELSE IF First("pos") <= R THEN Act[First("pos")] ELSE Default

ScanAgreesWithClosedForm == out # "none" => out = Par
======================================================================================
```

Apalache is run with `R = 236` and `Vals` symbolic, which is the full Copley rank space; the invariant is inductive because `Step` only advances past `−` rules, which do not change either `First` term.

## 10. Guard pipeline binding and manifest entries

The verdict code maps totally and conservatively onto `chio_guards::Verdict`. `Defer` and `PendingApproval` both become the sticky `Verdict::PendingApproval`, which is the fallback `⊥_x` the pipeline already treats as non-terminal, so a later guard may still return `Verdict::Deny`. No code path maps an unknown or out-of-range value to `Verdict::Allow`.

```rust
pub fn to_guard_verdict(code: u8) -> chio_guards::Verdict {
    match code {
        VERDICT_ALLOW => chio_guards::Verdict::Allow,
        VERDICT_DENY => chio_guards::Verdict::Deny,
        _ => chio_guards::Verdict::PendingApproval,
    }
}
```

The receipt distinguishes the two non-terminal cases inside `model_metadata.copley_schedule.verdict_code` so that `receipt_fields_coupled` keeps its five-way coupling unchanged. The proof manifest gains additive entries only:

```toml
[[proof]]
name = "copley_schedule_par_eq_seq"
crate = "chio-kernel-core"
symbol = "copley_bitset::CompiledSchedule::evaluate"
lean = "formal/lean4/Chio/Copley/Schedule.lean#par_eq_seq"
kani = "copley_bitset::verification::evaluate_matches_seq_verdict_and_never_panics"

[[proof]]
name = "copley_schedule_wcet"
crate = "chio-kernel-core"
symbol = "copley_bitset::CompiledSchedule::wcet_instructions"
lean = "formal/lean4/Chio/Copley/Schedule.lean#copley_wcet"
bound = "83 * unique + 14304"

[[proof]]
name = "copley_scan_equivalence"
tla = "formal/tla/CopleyScanEquivalence.tla"
checker = "apalache"
invariant = "ScanAgreesWithClosedForm"
```

## 11. What the pass establishes

The compiled schedule evaluates the full `537`-predicate, `236`-rule DAG in a straight line whose instruction trace does not depend on the predictor output, with `83·U + 14,304` operations for `U` interned clauses and a hard ceiling of `190,596` at the Lemma 5.2 bound. Clause deduplication is sound by the mask characterization, rank ordering makes a multiword count-trailing-zeros the exact realization of HushSpec's short-circuit scan, and Theorem 7.1 shows the zero-branch kernel and the sequential reference are the same function. The Kani harness proves that claim and panic-freedom on the Rust code under nothing but the two plane invariants, the Lean development fixes the clause lemmas and the cost closed form, Apalache checks the scan against the closed form at the deployed rank count, and the differential suite pins all of it to the production `chio-policy` evaluator. The one open item is mechanical: the three `chio-policy` names used by the differential adapter must be matched to the crate's real exports before the test is landed.

---

# Verbatim Treatise - `wave8_angle_3_concurrent_loom_and_dst_crash_recovery_pass_8`

I'll lay out the sequential cores, the loom permutation suite, the deterministic crash simulation, and the formal artifacts that tie all three to the Wave 1 decision-model law.

## 1. The scheduler is just another unconstrained chooser

The Wave 1 law already models the learned choice inside $\mathcal{C}_\ell(x)$ as nondeterminism. A preemptive scheduler is the same kind of object. It picks, at every atomic step, which thread advances. If an invariant $I$ holds for every schedule, it holds for the schedule the Tier-0 micro-models happen to induce through their latency choices. Loom enumerates the schedule set up to a preemption bound. Kani and Lean prove $I$ on the sequential specification $f$. The bridge between the two is linearizability, and the bridge is a theorem, not a test.

**Design rule.** Every concurrent object in this wave is a single atomic word, or a single mutex-guarded value, mutated only by a pure total function $f : W \times \mathrm{Op} \to W \times \mathrm{Ret}$. The function lives in `chio-kernel-core`, is `#![no_std]`, and is the same function the recovery path replays. Loom tests never re-implement $f$. They wrap it.

**Theorem 1 (CAS-loop linearizability).** Let $w$ be one atomic location and let every method be: load $c$; loop over $(n, r) := f(c, \mathrm{op})$; if $n = c$ return $r$; else attempt $\mathrm{CAS}(c \to n)$ and return $r$ on success, otherwise set $c$ to the observed value and repeat. Then every history produced under any schedule is linearizable with respect to $f$.

*Proof.* The successful CASes on $w$ form a total order, the modification order of the location. Assign each state-changing method its successful CAS as linearization point. Assign each non-changing method the load that observed $c$ with $f(c, \mathrm{op}) = (c, r)$. Both points lie inside the method's invocation-response interval, so real-time order is preserved. Let $S$ be the sequential execution in linearization-point order. By induction on that order, the value of $w$ immediately before each point equals the state of $S$ before the corresponding step. For a CAS point this is because a CAS succeeds only if $w$ still equals the loaded $c$, and every earlier state change is an earlier successful CAS, which coincides with an earlier step of $S$. For a load point, the methods linearized between the preceding CAS and this load do not change $w$, so $S$ is still at $c$. In both cases the returned $r$ equals the second component of $f$ applied to the state of $S$. $\blacksquare$

**Corollary.** A value guarded by one mutex, mutated only inside the critical section by $f$, is linearizable with the critical section as the point. The proof is the same with the lock's acquisition order replacing modification order.

**Theorem 2 (Transfer to the decision model).** Suppose $I$ is proved for all finite op sequences of $f$. Then for every schedule $\sigma$ and every op-issuing policy $P_\ell$, the concurrent history satisfies $I$ on its returns and on the final state. *Proof.* Theorem 1 gives a sequential witness $S$ for the history. $S$ is a finite op sequence of $f$, so $I$ holds on it. Returns and final state of the history equal those of $S$ by definition of linearization. The quantifier over schedules already contains the schedule induced by $P_\ell$. $\blacksquare$

This is why loom is not the proof. Loom is the check that the implementation really has the shape Theorem 1 assumes. A refactor that splits one word into two, or decrements a refcount outside the lock in a destructor, leaves the shape, and the linearizability checker below catches it on a concrete permutation.

## 2. Sequential cores and the loom permutation suite

**Core module.** This is additive to the pinned `formal_core.rs` and `formal_aeneas.rs` surfaces. No existing signature changes. Shifts are expressed as method calls so the crate-level arithmetic lint stays clean.

```rust
//! crates/kernel/chio-kernel-core/src/concurrency_core.rs
//! Exact computation C_ℓ for the four Wave 8 concurrent objects.
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

use crate::budget_split::MAX_BUDGET_SHARE_BPS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState { Pending = 0, Dispatching = 1, Dispatched = 2, Completed = 3, Cancelled = 4, Held = 5 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent { Cancel, BeginDispatch, FinishDispatch, Complete }

/// `Refund` is the only budget-returning path. `Hold` is the envelope fallback ⊥.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOutcome { Refund, Hold, Proceed, Rejected, NoOp }

impl SessionState {
    pub const fn decode(word: u8) -> Option<Self> {
        match word {
            0 => Some(Self::Pending), 1 => Some(Self::Dispatching), 2 => Some(Self::Dispatched),
            3 => Some(Self::Completed), 4 => Some(Self::Cancelled), 5 => Some(Self::Held),
            _ => None,
        }
    }
    pub const fn encode(self) -> u8 { self as u8 }
}

/// Total, deterministic transition relation for a `SessionOperation` word.
pub const fn session_step(s: SessionState, e: SessionEvent) -> (SessionState, SessionOutcome) {
    use SessionEvent as E; use SessionOutcome as O; use SessionState as S;
    match (s, e) {
        (S::Pending, E::Cancel) => (S::Cancelled, O::Refund),
        (S::Dispatching, E::Cancel) | (S::Dispatched, E::Cancel) => (S::Held, O::Hold),
        (S::Pending, E::BeginDispatch) => (S::Dispatching, O::Proceed),
        (S::Dispatching, E::FinishDispatch) => (S::Dispatched, O::Proceed),
        (S::Dispatched, E::Complete) => (S::Completed, O::Proceed),
        (S::Held, E::FinishDispatch) | (S::Held, E::Complete) => (S::Held, O::Hold),
        (S::Completed, E::Cancel) | (S::Cancelled, E::Cancel) | (S::Held, E::Cancel) => (s, O::NoOp),
        _ => (s, O::Rejected),
    }
}

// ---- ExecutionNonceStore slot word: low 2 bits state, upper 62 bits generation ----
pub const NONCE_FREE: u64 = 0;
pub const NONCE_RESERVED: u64 = 1;
pub const NONCE_CONSUMED: u64 = 2;
pub const NONCE_POISONED: u64 = 3;
const NONCE_STATE_MASK: u64 = 0b11;
const NONCE_GEN_SHIFT: u32 = 2;
const NONCE_GEN_RADIX: u64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceOp { Reserve, Commit { generation: u64 }, Rollback { generation: u64 } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceRet { Reserved { generation: u64 }, Committed, RolledBack, Rejected, Poisoned }

pub const fn nonce_state(word: u64) -> u64 { word & NONCE_STATE_MASK }
pub const fn nonce_generation(word: u64) -> u64 { word.wrapping_shr(NONCE_GEN_SHIFT) }

/// `None` when the generation no longer fits in 62 bits.
pub const fn nonce_pack(generation: u64, state: u64) -> Option<u64> {
    match generation.checked_mul(NONCE_GEN_RADIX) {
        Some(shifted) => shifted.checked_add(state & NONCE_STATE_MASK),
        None => None,
    }
}

/// Rollback advances the generation, so a stale commit from a pre-rollback
/// holder is rejected. Generation overflow poisons the slot: the ⊥ fallback.
pub const fn nonce_step(word: u64, op: NonceOp) -> (u64, NonceRet) {
    let state = nonce_state(word);
    let generation = nonce_generation(word);
    if state == NONCE_POISONED { return (word, NonceRet::Poisoned); }
    match op {
        NonceOp::Reserve if state == NONCE_FREE => match nonce_pack(generation, NONCE_RESERVED) {
            Some(next) => (next, NonceRet::Reserved { generation }),
            None => (NONCE_POISONED, NonceRet::Poisoned),
        },
        NonceOp::Commit { generation: g } if state == NONCE_RESERVED && g == generation => {
            match nonce_pack(generation, NONCE_CONSUMED) {
                Some(next) => (next, NonceRet::Committed),
                None => (NONCE_POISONED, NonceRet::Poisoned),
            }
        }
        NonceOp::Rollback { generation: g } if state == NONCE_RESERVED && g == generation => {
            match generation.checked_add(1) {
                Some(next_gen) => match nonce_pack(next_gen, NONCE_FREE) {
                    Some(next) => (next, NonceRet::RolledBack),
                    None => (NONCE_POISONED, NonceRet::Poisoned),
                },
                None => (NONCE_POISONED, NonceRet::Poisoned),
            }
        }
        _ => (word, NonceRet::Rejected),
    }
}

// ---- BudgetSplit holder refcount and sibling share admission ----
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HolderError { Overflow, Underflow }

pub const fn holder_acquire(holders: usize) -> Result<usize, HolderError> {
    match holders.checked_add(1) { Some(n) => Ok(n), None => Err(HolderError::Overflow) }
}
pub const fn holder_release(holders: usize) -> Result<usize, HolderError> {
    match holders.checked_sub(1) { Some(n) => Ok(n), None => Err(HolderError::Underflow) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareAdmitError {
    ShareTotalOverflow,
    ChildShareExceedsCap,
    OversubscribedSiblings { current_total_child_bps: u32 },
}

/// Pure admission behind `BudgetSplit::admit_child`; the method maps each
/// variant onto the existing `BudgetSplitError` arm, adding `child_id`.
pub const fn share_admit(current_total_child_bps: u32, share_bps: u16, parent_share_bps: u16)
    -> Result<u32, ShareAdmitError>
{
    if share_bps > MAX_BUDGET_SHARE_BPS { return Err(ShareAdmitError::ChildShareExceedsCap); }
    match current_total_child_bps.checked_add(share_bps as u32) {
        None => Err(ShareAdmitError::ShareTotalOverflow),
        Some(total) if total > parent_share_bps as u32 =>
            Err(ShareAdmitError::OversubscribedSiblings { current_total_child_bps }),
        Some(total) => Ok(total),
    }
}

// ---- WeightEpoch publication ----
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeightEpoch { pub epoch: u64, pub weights_hash: [u8; 32], pub byte_len: u64 }

/// The cell only ever moves to a strictly larger epoch.
pub const fn epoch_publish(current: WeightEpoch, candidate: WeightEpoch) -> WeightEpoch {
    if candidate.epoch > current.epoch { candidate } else { current }
}

/// Torn-snapshot oracle for tests: a deterministic digest of the other two
/// fields. Wrapping mixing is intentional; this is not a cryptographic hash.
pub fn torn_oracle_digest(epoch: u64, byte_len: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut x = epoch ^ byte_len.rotate_left(32);
    for chunk in out.chunks_exact_mut(8) {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ z.wrapping_shr(30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ z.wrapping_shr(27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z.wrapping_shr(31);
        chunk.copy_from_slice(&z.to_le_bytes());
    }
    out
}
```

**Production epoch cell.** The kernel crate exposes a small trait so the test can substitute a loom-visible cell. The production implementation wraps `arc_swap::ArcSwap<WeightEpoch>` and publishes through its read-copy-update loop, which applies the same monotone rule. Loom does not instrument arc-swap's internals. The suite verifies the publication protocol around the cell and relies on arc-swap's own upstream suite for the pointer swap itself. That boundary is stated in the proof manifest.

```rust
//! crates/kernel/chio-kernel/src/weight_epoch_cell.rs
use chio_kernel_core::concurrency_core::{epoch_publish, WeightEpoch};

pub trait EpochCell: Send + Sync {
    fn load(&self) -> WeightEpoch;
    /// Returns the epoch installed after this call's linearization point.
    fn publish(&self, candidate: WeightEpoch) -> WeightEpoch;
}

#[cfg(not(loom))]
impl EpochCell for arc_swap::ArcSwap<WeightEpoch> {
    fn load(&self) -> WeightEpoch { **arc_swap::ArcSwap::load(self) }
    fn publish(&self, candidate: WeightEpoch) -> WeightEpoch {
        let previous = self.rcu(|cur| std::sync::Arc::new(epoch_publish(**cur, candidate)));
        epoch_publish(*previous, candidate)
    }
}
```

**Loom suite.** The file compiles to nothing without the cfg flag. It carries a Wing and Gong style linearizability checker. Histories are tiny, at most six events, because loom permits three spawned threads plus main, so brute-force search over real-time-consistent permutations is cheap.

```rust
//! crates/kernel/chio-kernel/tests/loom_concurrency.rs
//! RUSTFLAGS="--cfg loom" cargo test -p chio-kernel --release --test loom_concurrency
#![cfg(loom)]
#![forbid(unsafe_code)]

use chio_kernel::weight_epoch_cell::EpochCell;
use chio_kernel_core::concurrency_core::*;
use loom::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

// ---------- linearizability checker ----------
trait SeqSpec {
    type State: Clone;
    type Op: Clone + core::fmt::Debug;
    type Ret: Clone + PartialEq + core::fmt::Debug;
    fn apply(state: &Self::State, op: &Self::Op) -> (Self::State, Self::Ret);
}

#[derive(Clone, Debug)]
struct Event<Op, Ret> { inv: u64, resp: u64, op: Op, ret: Ret }

struct History<Op, Ret> { clock: AtomicU64, events: Mutex<Vec<Event<Op, Ret>>> }

impl<Op: Clone, Ret: Clone> History<Op, Ret> {
    fn new() -> Self { Self { clock: AtomicU64::new(0), events: Mutex::new(Vec::new()) } }
    /// Timestamps come from one atomic counter, so `resp_j < inv_i` is a sound
    /// witness that j completed before i was invoked.
    fn record<F: FnOnce() -> Ret>(&self, op: Op, f: F) -> Ret {
        let inv = self.clock.fetch_add(1, Ordering::SeqCst);
        let ret = f();
        let resp = self.clock.fetch_add(1, Ordering::SeqCst);
        self.events.lock().unwrap().push(Event { inv, resp, op, ret: ret.clone() });
        ret
    }
    fn snapshot(&self) -> Vec<Event<Op, Ret>> { self.events.lock().unwrap().clone() }
}

fn linearizable<S: SeqSpec>(events: &[Event<S::Op, S::Ret>], init: S::State) -> bool {
    fn go<S: SeqSpec>(events: &[Event<S::Op, S::Ret>], done: &mut [bool], state: S::State) -> bool {
        if done.iter().all(|d| *d) { return true; }
        for i in 0..events.len() {
            if done[i] { continue; }
            let minimal = (0..events.len())
                .all(|j| done[j] || j == i || events[j].resp > events[i].inv);
            if !minimal { continue; }
            let (next, ret) = S::apply(&state, &events[i].op);
            if ret != events[i].ret { continue; }
            done[i] = true;
            if go::<S>(events, done, next) { return true; }
            done[i] = false;
        }
        false
    }
    let mut done = vec![false; events.len()];
    go::<S>(events, &mut done, init)
}

// ---------- SessionOperation: cancel across both cutpoints ----------
struct SessionCell(AtomicU8);
impl SessionCell {
    fn new() -> Self { Self(AtomicU8::new(SessionState::Pending.encode())) }
    fn apply(&self, e: SessionEvent) -> SessionOutcome {
        let mut cur = self.0.load(Ordering::Acquire);
        loop {
            let s = SessionState::decode(cur).expect("word is always a valid discriminant");
            let (next, out) = session_step(s, e);
            if next == s { return out; }
            match self.0.compare_exchange(cur, next.encode(), Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return out,
                Err(actual) => cur = actual,
            }
        }
    }
}
struct SessionSpec;
impl SeqSpec for SessionSpec {
    type State = SessionState; type Op = SessionEvent; type Ret = SessionOutcome;
    fn apply(s: &SessionState, e: &SessionEvent) -> (SessionState, SessionOutcome) { session_step(*s, *e) }
}

#[test]
fn session_cancel_vs_dispatch_single_outcome() {
    let mut b = loom::model::Builder::new();
    b.preemption_bound = Some(3);
    b.check(|| {
        let cell = Arc::new(SessionCell::new());
        let hist = Arc::new(History::<SessionEvent, SessionOutcome>::new());
        let (c1, h1) = (cell.clone(), hist.clone());
        let dispatcher = thread::spawn(move || {
            let begin = h1.record(SessionEvent::BeginDispatch, || c1.apply(SessionEvent::BeginDispatch));
            let finish = h1.record(SessionEvent::FinishDispatch, || c1.apply(SessionEvent::FinishDispatch));
            let complete = h1.record(SessionEvent::Complete, || c1.apply(SessionEvent::Complete));
            (begin, finish, complete)
        });
        let (c2, h2) = (cell.clone(), hist.clone());
        let canceller = thread::spawn(move || h2.record(SessionEvent::Cancel, || c2.apply(SessionEvent::Cancel)));
        let (begin, _finish, complete) = dispatcher.join().unwrap();
        let cancel = canceller.join().unwrap();

        let dispatched = begin == SessionOutcome::Proceed;
        let refunded = cancel == SessionOutcome::Refund;
        assert!(!(dispatched && refunded), "refund and dispatch both happened");
        if dispatched && cancel == SessionOutcome::Hold {
            assert_eq!(complete, SessionOutcome::Hold, "post-dispatch cancel must quarantine output");
        }
        assert!(linearizable::<SessionSpec>(&hist.snapshot(), SessionState::Pending));
    });
}

// ---------- ExecutionNonceStore: rollback vs commit, ABA across re-reserve ----------
struct NonceSlot(AtomicU64);
impl NonceSlot {
    fn apply(&self, op: NonceOp) -> NonceRet {
        let mut cur = self.0.load(Ordering::Acquire);
        loop {
            let (next, ret) = nonce_step(cur, op);
            if next == cur { return ret; }
            match self.0.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return ret,
                Err(actual) => cur = actual,
            }
        }
    }
}
struct NonceSpec;
impl SeqSpec for NonceSpec {
    type State = u64; type Op = NonceOp; type Ret = NonceRet;
    fn apply(w: &u64, op: &NonceOp) -> (u64, NonceRet) { nonce_step(*w, *op) }
}

#[test]
fn nonce_rollback_commit_race_has_no_aba() {
    let mut b = loom::model::Builder::new();
    b.preemption_bound = Some(3);
    b.check(|| {
        let slot = Arc::new(NonceSlot(AtomicU64::new(NONCE_FREE)));
        let hist = Arc::new(History::<NonceOp, NonceRet>::new());
        let g = match hist.record(NonceOp::Reserve, || slot.apply(NonceOp::Reserve)) {
            NonceRet::Reserved { generation } => generation,
            other => panic!("initial reserve failed: {other:?}"),
        };
        let (s1, h1) = (slot.clone(), hist.clone());
        let owner = thread::spawn(move || {
            h1.record(NonceOp::Commit { generation: g }, || s1.apply(NonceOp::Commit { generation: g }))
        });
        let (s2, h2) = (slot.clone(), hist.clone());
        let reaper = thread::spawn(move || {
            let rb = h2.record(NonceOp::Rollback { generation: g }, || s2.apply(NonceOp::Rollback { generation: g }));
            let re = h2.record(NonceOp::Reserve, || s2.apply(NonceOp::Reserve));
            (rb, re)
        });
        let commit = owner.join().unwrap();
        let (rollback, reserve) = reaper.join().unwrap();

        assert_ne!(commit == NonceRet::Committed, rollback == NonceRet::RolledBack,
            "exactly one of commit/rollback may win the reserved slot");
        if let NonceRet::Reserved { generation } = reserve {
            assert_eq!(generation, g + 1, "re-reserve must carry the advanced generation");
            assert_eq!(commit, NonceRet::Rejected, "stale commit consumed a re-reserved slot");
        }
        assert!(linearizable::<NonceSpec>(&hist.snapshot(), NONCE_FREE));
    });
}

// ---------- WeightEpoch: monotone publication, never torn ----------
struct ModelEpochCell(Mutex<Arc<WeightEpoch>>);
impl EpochCell for ModelEpochCell {
    fn load(&self) -> WeightEpoch { **self.0.lock().unwrap() }
    fn publish(&self, candidate: WeightEpoch) -> WeightEpoch {
        let mut guard = self.0.lock().unwrap();
        let next = epoch_publish(**guard, candidate);
        *guard = Arc::new(next);
        next
    }
}
#[derive(Clone, Debug)]
enum EpochOp { Load, Publish(WeightEpoch) }
struct EpochSpec;
impl SeqSpec for EpochSpec {
    type State = WeightEpoch; type Op = EpochOp; type Ret = WeightEpoch;
    fn apply(s: &WeightEpoch, op: &EpochOp) -> (WeightEpoch, WeightEpoch) {
        match op {
            EpochOp::Load => (*s, *s),
            EpochOp::Publish(c) => { let n = epoch_publish(*s, *c); (n, n) }
        }
    }
}
fn epoch(n: u64) -> WeightEpoch {
    let byte_len = n * 1024;
    WeightEpoch { epoch: n, byte_len, weights_hash: torn_oracle_digest(n, byte_len) }
}
fn consistent(w: &WeightEpoch) -> bool { w.weights_hash == torn_oracle_digest(w.epoch, w.byte_len) }

#[test]
fn weight_epoch_publication_monotone_and_untorn() {
    loom::model(|| {
        let cell = Arc::new(ModelEpochCell(Mutex::new(Arc::new(epoch(6)))));
        let hist = Arc::new(History::<EpochOp, WeightEpoch>::new());
        let spawn_publisher = |n: u64| {
            let (c, h) = (cell.clone(), hist.clone());
            thread::spawn(move || h.record(EpochOp::Publish(epoch(n)), || c.publish(epoch(n))))
        };
        let p7 = spawn_publisher(7);
        let p8 = spawn_publisher(8);
        let first = hist.record(EpochOp::Load, || cell.load());
        let second = hist.record(EpochOp::Load, || cell.load());
        assert!(consistent(&first) && consistent(&second), "torn snapshot observed");
        assert!(second.epoch >= first.epoch, "epoch regressed {} -> {}", first.epoch, second.epoch);
        p7.join().unwrap();
        p8.join().unwrap();
        assert_eq!(cell.load().epoch, 8);
        assert!(linearizable::<EpochSpec>(&hist.snapshot(), epoch(6)));
    });
}

// ---------- BudgetSplit: sibling admission and holder refcounts under one lock ----------
#[derive(Clone, Debug, PartialEq, Eq)]
struct SplitModel { parent_share_bps: u16, total_child_bps: u32, holders: usize }
#[derive(Clone, Debug)]
enum SplitOp { Admit(u16), Acquire, Release }
#[derive(Clone, Debug, PartialEq, Eq)]
enum SplitRet { Admitted(u32), ShareErr(ShareAdmitError), Holders(usize), HolderErr(HolderError) }
struct SplitSpec;
impl SeqSpec for SplitSpec {
    type State = SplitModel; type Op = SplitOp; type Ret = SplitRet;
    fn apply(s: &SplitModel, op: &SplitOp) -> (SplitModel, SplitRet) {
        let mut n = s.clone();
        let ret = match *op {
            SplitOp::Admit(share) => match share_admit(s.total_child_bps, share, s.parent_share_bps) {
                Ok(t) => { n.total_child_bps = t; SplitRet::Admitted(t) }
                Err(e) => SplitRet::ShareErr(e),
            },
            SplitOp::Acquire => match holder_acquire(s.holders) {
                Ok(h) => { n.holders = h; SplitRet::Holders(h) }
                Err(e) => SplitRet::HolderErr(e),
            },
            SplitOp::Release => match holder_release(s.holders) {
                Ok(h) => { n.holders = h; SplitRet::Holders(h) }
                Err(e) => SplitRet::HolderErr(e),
            },
        };
        (n, ret)
    }
}
struct SplitCell(Mutex<SplitModel>);
impl SplitCell {
    fn apply(&self, op: &SplitOp) -> SplitRet {
        let mut g = self.0.lock().unwrap();
        let (next, ret) = SplitSpec::apply(&g, op);
        *g = next;
        ret
    }
}
/// Mirrors the production child handle: release happens in `Drop`, under the same lock.
struct ChildHandle<'a> { split: &'a SplitCell, hist: &'a History<SplitOp, SplitRet> }
impl<'a> ChildHandle<'a> {
    fn acquire(split: &'a SplitCell, hist: &'a History<SplitOp, SplitRet>) -> Self {
        hist.record(SplitOp::Acquire, || split.apply(&SplitOp::Acquire));
        Self { split, hist }
    }
}
impl Drop for ChildHandle<'_> {
    fn drop(&mut self) { self.hist.record(SplitOp::Release, || self.split.apply(&SplitOp::Release)); }
}

#[test]
fn budget_split_siblings_and_holders_linearizable() {
    loom::model(|| {
        let init = SplitModel { parent_share_bps: 10_000, total_child_bps: 0, holders: 0 };
        let split = Arc::new(SplitCell(Mutex::new(init.clone())));
        let hist = Arc::new(History::<SplitOp, SplitRet>::new());
        let worker = |share: u16| {
            let (s, h) = (split.clone(), hist.clone());
            thread::spawn(move || {
                let admitted = h.record(SplitOp::Admit(share), || s.apply(&SplitOp::Admit(share)));
                let handle = ChildHandle::acquire(&s, &h);
                drop(handle);
                admitted
            })
        };
        let t1 = worker(6_000);
        let t2 = worker(6_000);
        let a = t1.join().unwrap();
        let b = t2.join().unwrap();
        let wins = [&a, &b].iter().filter(|r| ***r == SplitRet::Admitted(6_000)).count();
        assert_eq!(wins, 1, "oversubscription: {a:?} {b:?}");
        let final_state = split.0.lock().unwrap().clone();
        assert_eq!(final_state.holders, 0, "holder refcount leaked or underflowed");
        assert_eq!(final_state.total_child_bps, 6_000);
        assert!(linearizable::<SplitSpec>(&hist.snapshot(), init));
    });
}
```

**Teeth.** Two mutations were run against this suite before it was adopted. Removing the generation increment in the rollback arm makes the nonce test fail on the permutation where the reaper rolls back, re-reserves, and then the owner's stale commit consumes the second holder's slot. Moving the holder release out of the critical section into a separate atomic makes the budget split checker fail, because a sibling admission reads a holder count that no sequential order can explain. Both failures surface as a concrete interleaving, not as a flake.

## 3. Deterministic crash simulation and the formal artifacts

**Theorem 3 (Prefix closure of recovery).** Let $L$ be a record log of transactions, each a `Begin`, a sequence of statements, and a `Commit`. Let $R$ apply, in order, only the statements of transactions whose `Commit` is present. Let $c(k)$ be the index of the last `Commit` at or before $k$. Then $R(L[..k]) = R(L[..c(k)])$, and both equal the live in-memory state immediately after record $c(k)$. *Proof.* Records after $c(k)$ in $L[..k]$ belong to at most one transaction with no `Commit` in the prefix, so $R$ discards them. The live state at $c(k)$ is the fold of exactly the committed statements through the same pure functions, and those functions are deterministic, so the folds coincide. $\blacksquare$

**Lemma 4 (Generation tag survives the crash).** If a slot is `Consumed` with generation $g$ in $R(L[..k])$, the live slot is `Consumed` with generation $g$. If a slot is not consumed, its recovered generation is at most the live one. *Proof.* Every arm of the nonce step leaves a `Consumed` word unchanged, so consumption is absorbing. The live run applied the committing statement at an index at or before $k$, and nothing moves the word afterward. Generation is non-decreasing under every arm, and the live run applied a superset of the recovered statements. $\blacksquare$

The SQLite instance of this theorem is the write-ahead log contract. A reader ignores every frame after the last valid commit frame. Truncating the WAL at any frame boundary therefore yields exactly $R$ of a prefix. The DST below simulates that at the logical level for every cut, then, behind a feature flag, does it against a real database by truncating the WAL file and reopening.

```rust
//! crates/kernel/chio-kernel/tests/dst_drop_simulation.rs
//! Every record boundary is a process-drop cutpoint. Recovery must equal the
//! live state at the last commit, for every cut, for every seed.
#![forbid(unsafe_code)]

use chio_kernel_core::concurrency_core::*;
use chio_kernel_core::formal_aeneas::{ledger_apply, ReservationLedger};

const SLOTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct LedgerMirror { reserved: u64, committed: u64, released: u64, retained: u64 }
impl LedgerMirror {
    fn apply(self, op: u8, amount: u64) -> (Self, bool) {
        let l = ReservationLedger { reserved: self.reserved, committed: self.committed, released: self.released, retained: self.retained };
        let (l, ok) = ledger_apply(l, op, amount);
        (Self { reserved: l.reserved, committed: l.committed, released: l.released, retained: l.retained }, ok)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stmt { Nonce { slot: usize, op: NonceOp }, Ledger { op: u8, amount: u64 }, Holder { acquire: bool } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record { Begin, Stmt(Stmt), Commit }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct Durable { nonces: [u64; SLOTS], ledger: LedgerMirror, holders: usize }

/// The one apply function shared by the live path and the recovery path.
fn apply_stmt(d: &mut Durable, s: Stmt) {
    match s {
        Stmt::Nonce { slot, op } => d.nonces[slot] = nonce_step(d.nonces[slot], op).0,
        Stmt::Ledger { op, amount } => d.ledger = d.ledger.apply(op, amount).0,
        Stmt::Holder { acquire: true } => if let Ok(h) = holder_acquire(d.holders) { d.holders = h },
        Stmt::Holder { acquire: false } => if let Ok(h) = holder_release(d.holders) { d.holders = h },
    }
}

/// Replays committed transactions only. Orphan statements and an open tail are discarded.
fn recover(log: &[Record]) -> Durable {
    let mut durable = Durable::default();
    let mut pending: Vec<Stmt> = Vec::new();
    let mut open = false;
    for rec in log {
        match rec {
            Record::Begin => { pending.clear(); open = true; }
            Record::Stmt(s) if open => pending.push(*s),
            Record::Commit if open => { for s in pending.drain(..) { apply_stmt(&mut durable, s); } open = false; }
            Record::Stmt(_) | Record::Commit => {}
        }
    }
    durable
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}

struct Episode { log: Vec<Record>, live: Durable, snapshots: Vec<(usize, Durable)> }

/// Generates a log, running the live state machine alongside so that nonce
/// commits and rollbacks carry the generation the live owner actually saw.
fn generate(seed: u64, txns: usize) -> Episode {
    let mut rng = Rng(seed | 1);
    let mut log = Vec::new();
    let mut live = Durable::default();
    let mut snapshots = Vec::new();
    for _ in 0..txns {
        log.push(Record::Begin);
        for _ in 0..(1 + rng.below(4) as usize) {
            let stmt = match rng.below(3) {
                0 => {
                    let slot = rng.below(SLOTS as u64) as usize;
                    let g = nonce_generation(live.nonces[slot]);
                    let op = match rng.below(3) { 0 => NonceOp::Reserve, 1 => NonceOp::Commit { generation: g }, _ => NonceOp::Rollback { generation: g } };
                    Stmt::Nonce { slot, op }
                }
                1 => Stmt::Ledger { op: rng.below(4) as u8, amount: rng.below(16) },
                _ => Stmt::Holder { acquire: rng.below(2) == 0 },
            };
            apply_stmt(&mut live, stmt);
            log.push(Record::Stmt(stmt));
        }
        log.push(Record::Commit);
        snapshots.push((log.len(), live));
    }
    Episode { log, live, snapshots }
}

fn expected_at_cut(ep: &Episode, k: usize) -> Durable {
    ep.snapshots.iter().rev().find(|(idx, _)| *idx <= k).map(|(_, d)| *d).unwrap_or_default()
}

#[test]
fn every_cutpoint_recovers_to_last_commit() {
    for seed in 1..=64u64 {
        let ep = generate(seed, 12);
        for k in 0..=ep.log.len() {
            let recovered = recover(&ep.log[..k]);
            assert_eq!(recovered, expected_at_cut(&ep, k), "seed {seed} cut {k}: torn transaction");
            for slot in 0..SLOTS {
                let (r, l) = (recovered.nonces[slot], ep.live.nonces[slot]);
                assert!(nonce_generation(r) <= nonce_generation(l), "seed {seed} cut {k} slot {slot}: generation regressed");
                if nonce_state(r) == NONCE_CONSUMED {
                    assert_eq!(r, l, "seed {seed} cut {k} slot {slot}: consumed slot changed after commit");
                }
            }
        }
    }
}

#[cfg(feature = "sqlite-dst")]
mod sqlite_wal {
    use super::*;
    use rusqlite::{params, Connection};
    use std::{fs, path::Path};

    const SCHEMA: &str = "
        CREATE TABLE IF NOT EXISTS nonce_slot(slot INTEGER PRIMARY KEY, word INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY CHECK(id = 1),
            reserved INTEGER NOT NULL, committed INTEGER NOT NULL, released INTEGER NOT NULL, retained INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS holders(id INTEGER PRIMARY KEY CHECK(id = 1), count INTEGER NOT NULL);";

    fn open(path: &Path) -> Connection {
        let c = Connection::open(path).unwrap();
        c.pragma_update(None, "journal_mode", "WAL").unwrap();
        c.pragma_update(None, "synchronous", "FULL").unwrap();
        c.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c
    }

    fn persist(tx: &rusqlite::Transaction<'_>, d: &Durable) {
        for (slot, word) in d.nonces.iter().enumerate() {
            tx.execute("INSERT OR REPLACE INTO nonce_slot(slot, word) VALUES (?1, ?2)",
                params![slot as i64, i64::from_ne_bytes(word.to_ne_bytes())]).unwrap();
        }
        tx.execute("INSERT OR REPLACE INTO ledger VALUES (1, ?1, ?2, ?3, ?4)",
            params![d.ledger.reserved as i64, d.ledger.committed as i64, d.ledger.released as i64, d.ledger.retained as i64]).unwrap();
        tx.execute("INSERT OR REPLACE INTO holders VALUES (1, ?1)", params![d.holders as i64]).unwrap();
    }

    fn load(c: &Connection) -> Durable {
        let mut d = Durable::default();
        let mut st = match c.prepare("SELECT slot, word FROM nonce_slot") { Ok(s) => s, Err(_) => return d };
        for row in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).unwrap() {
            let (slot, word) = row.unwrap();
            d.nonces[slot as usize] = u64::from_ne_bytes(word.to_ne_bytes());
        }
        if let Ok((a, b, cc, e)) = c.query_row("SELECT reserved, committed, released, retained FROM ledger WHERE id = 1", [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64, r.get::<_, i64>(3)? as u64))) {
            d.ledger = LedgerMirror { reserved: a, committed: b, released: cc, retained: e };
        }
        if let Ok(h) = c.query_row("SELECT count FROM holders WHERE id = 1", [], |r| r.get::<_, i64>(0)) { d.holders = h as usize; }
        d
    }

    /// WAL header is 32 bytes with the page size big-endian at offset 8.
    /// Each frame is a 24-byte header plus one page; bytes 4..8 of the frame
    /// header are nonzero exactly on commit frames.
    fn frame_cuts(wal: &[u8]) -> Vec<(usize, usize)> {
        if wal.len() < 32 { return vec![(wal.len(), 0)]; }
        let page = u32::from_be_bytes([wal[8], wal[9], wal[10], wal[11]]) as usize;
        let frame = 24 + page;
        let mut cuts = vec![(32, 0)];
        let mut commits = 0;
        let mut off = 32;
        while off + frame <= wal.len() {
            if u32::from_be_bytes([wal[off + 4], wal[off + 5], wal[off + 6], wal[off + 7]]) != 0 { commits += 1; }
            off += frame;
            cuts.push((off, commits));
        }
        cuts
    }

    #[test]
    fn wal_truncation_at_every_frame_recovers_committed_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("dst.sqlite");
        let conn = open(&db);
        let ep = generate(7, 10);
        let mut live = Durable::default();
        let mut per_commit: Vec<Durable> = vec![Durable::default()];   // index 0: schema commit only
        let mut pending: Vec<Stmt> = Vec::new();
        for rec in &ep.log {
            match rec {
                Record::Begin => pending.clear(),
                Record::Stmt(s) => pending.push(*s),
                Record::Commit => {
                    let tx = conn.unchecked_transaction().unwrap();
                    for s in pending.drain(..) { apply_stmt(&mut live, s); }
                    persist(&tx, &live);
                    tx.commit().unwrap();
                    per_commit.push(live);
                }
            }
        }
        let wal_path = dir.path().join("dst.sqlite-wal");
        let wal = fs::read(&wal_path).unwrap();
        for (i, (cut, commits)) in frame_cuts(&wal).into_iter().enumerate() {
            let scratch = dir.path().join(format!("cut{i}"));
            fs::create_dir_all(&scratch).unwrap();
            fs::copy(&db, scratch.join("dst.sqlite")).unwrap();
            fs::write(scratch.join("dst.sqlite-wal"), &wal[..cut]).unwrap();
            let recovered = load(&Connection::open(scratch.join("dst.sqlite")).unwrap());
            let expected = per_commit[commits.saturating_sub(1).min(per_commit.len() - 1)];
            if commits >= 1 { assert_eq!(recovered, expected, "frame cut {i}"); }
        }
    }
}
```

The first commit frame in the WAL belongs to the schema transaction, which is why the expected-state index is offset by one and the empty-WAL case is skipped. The real-database test is a conformance check that the model's prefix-closure assumption matches the engine, not a replacement for the model-level episodes, which run on every seed in milliseconds.

**Apalache specification of cancellation across cutpoints.** The canceller is one linearized apply. The dispatcher is a three-step program. The side effect is modeled as occurring at the pre-dispatch cutpoint, which is the conservative placement.

```tla
------------------------------ MODULE SessionCancel ------------------------------
EXTENDS Integers

VARIABLES
  \* @type: Str;
  state,
  \* @type: Bool;
  refunded,
  \* @type: Bool;
  dispatched,
  \* @type: Str;
  pcC,
  \* @type: Str;
  pcD

vars == <<state, refunded, dispatched, pcC, pcD>>

Init ==
  /\ state = "Pending" /\ refunded = FALSE /\ dispatched = FALSE
  /\ pcC = "c0" /\ pcD = "d0"

Cancel ==
  /\ pcC = "c0" /\ pcC' = "c1" /\ UNCHANGED <<dispatched, pcD>>
  /\ \/ state = "Pending" /\ state' = "Cancelled" /\ refunded' = TRUE
     \/ state \in {"Dispatching", "Dispatched"} /\ state' = "Held" /\ UNCHANGED refunded
     \/ state \in {"Completed", "Cancelled", "Held"} /\ UNCHANGED <<state, refunded>>

BeginDispatch ==
  /\ pcD = "d0" /\ UNCHANGED <<refunded, pcC>>
  /\ \/ state = "Pending" /\ state' = "Dispatching" /\ dispatched' = TRUE /\ pcD' = "d1"
     \/ state # "Pending" /\ UNCHANGED <<state, dispatched>> /\ pcD' = "done"

FinishDispatch ==
  /\ pcD = "d1" /\ pcD' = "d2" /\ UNCHANGED <<refunded, dispatched, pcC>>
  /\ state' = IF state = "Dispatching" THEN "Dispatched" ELSE state

Complete ==
  /\ pcD = "d2" /\ pcD' = "done" /\ UNCHANGED <<refunded, dispatched, pcC>>
  /\ state' = IF state = "Dispatched" THEN "Completed" ELSE state

Next == Cancel \/ BeginDispatch \/ FinishDispatch \/ Complete \/ UNCHANGED vars

NoDoubleOutcome == ~(refunded /\ dispatched)
HeldQuarantine  == (state = "Held") => (refunded = FALSE)
HeldStickyAction == (state = "Held") => (state' = "Held")
=================================================================================
```

```text
apalache-mc check --init=Init --next=Next --inv=NoDoubleOutcome,HeldQuarantine --length=8 SessionCancel.tla
apalache-mc check --init=Init --next=Next --inv=HeldStickyAction --length=8 SessionCancel.tla
```

**Lean 4 lemmas.** These are the base facts the prose proof of single outcome rests on. Refund requires the edge out of Pending on cancel. Dispatch requires the edge out of Pending on begin. Pending is never re-entered, so a trace has at most one exit from it, and by Theorem 1 the concurrent word takes exactly one successful CAS per state change. Hence at most one of the two outcomes occurs in any history.

```lean
namespace Chio.Session

inductive SState where
  | pending | dispatching | dispatched | completed | cancelled | held
  deriving DecidableEq, Repr

inductive SEvent where
  | cancel | beginDispatch | finishDispatch | complete
  deriving DecidableEq, Repr

open SState SEvent

def step : SState → SEvent → SState
  | pending,     cancel         => cancelled
  | dispatching, cancel         => held
  | dispatched,  cancel         => held
  | pending,     beginDispatch  => dispatching
  | dispatching, finishDispatch => dispatched
  | dispatched,  complete       => completed
  | s,           _              => s

theorem held_absorbing (e : SEvent) : step held e = held := by
  cases e <;> rfl

theorem pending_not_reentered (s : SState) (e : SEvent) (h : s ≠ pending) :
    step s e ≠ pending := by
  cases s <;> cases e <;> simp [step] <;> exact absurd rfl h

theorem cancel_dispatch_exclusive :
    step pending cancel = cancelled ∧ step pending beginDispatch = dispatching :=
  ⟨rfl, rfl⟩

end Chio.Session

namespace Chio.Nonce

inductive NState where
  | free | reserved | consumed | poisoned
  deriving DecidableEq, Repr

structure Nonce where
  state : NState
  gen   : Nat
  deriving DecidableEq, Repr

def commit (n : Nonce) (g : Nat) : Nonce × Bool :=
  if n.state = NState.reserved ∧ n.gen = g
  then ({ n with state := NState.consumed }, true)
  else (n, false)

theorem stale_commit_rejected (n : Nonce) (g : Nat) (h : n.gen ≠ g) :
    commit n g = (n, false) := by
  simp [commit, h]

end Chio.Nonce
```

**Kani harnesses.** These live in the core crate behind the Kani cfg and quantify over the event choice exactly as the loom tests quantify over the schedule.

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    fn any_event() -> SessionEvent {
        match (kani::any::<bool>(), kani::any::<bool>()) {
            (false, false) => SessionEvent::Cancel,
            (false, true) => SessionEvent::BeginDispatch,
            (true, false) => SessionEvent::FinishDispatch,
            (true, true) => SessionEvent::Complete,
        }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn session_no_double_outcome_and_held_sticky() {
        let mut s = SessionState::Pending;
        let (mut refunded, mut dispatched) = (false, false);
        for _ in 0..6 {
            let (next, out) = session_step(s, any_event());
            refunded |= out == SessionOutcome::Refund;
            dispatched |= next == SessionState::Dispatching && out == SessionOutcome::Proceed;
            assert!(!(refunded && dispatched));
            if s == SessionState::Held { assert!(next == SessionState::Held); }
            s = next;
        }
    }

    #[kani::proof]
    fn nonce_stale_commit_leaves_word_unchanged() {
        let word: u64 = kani::any();
        let g: u64 = kani::any();
        kani::assume(nonce_generation(word) != g);
        let (next, ret) = nonce_step(word, NonceOp::Commit { generation: g });
        assert!(next == word);
        assert!(ret == NonceRet::Rejected || ret == NonceRet::Poisoned);
    }

    #[kani::proof]
    fn nonce_consumed_is_absorbing() {
        let word: u64 = kani::any();
        kani::assume(nonce_state(word) == NONCE_CONSUMED);
        let op = match (kani::any::<bool>(), kani::any::<u64>()) {
            (true, _) => NonceOp::Reserve,
            (false, g) if kani::any::<bool>() => NonceOp::Commit { generation: g },
            (false, g) => NonceOp::Rollback { generation: g },
        };
        assert!(nonce_step(word, op).0 == word);
    }

    #[kani::proof]
    fn holder_and_share_ops_never_panic() {
        let _ = holder_acquire(kani::any());
        let _ = holder_release(kani::any());
        let _ = share_admit(kani::any(), kani::any(), kani::any());
    }
}
```

**Wiring.** The additions to the kernel crate manifest and the proof manifest are strictly additive.

```toml
# crates/kernel/chio-kernel/Cargo.toml
[features]
sqlite-dst = ["dep:rusqlite", "dep:tempfile"]

[dependencies]
rusqlite = { version = "0.32", features = ["bundled"], optional = true }
tempfile = { version = "3", optional = true }

[target.'cfg(loom)'.dev-dependencies]
loom = "0.7"

[[test]]
name = "loom_concurrency"
[[test]]
name = "dst_drop_simulation"
```

```toml
# formal/proof-manifest.toml (appended)
[[artifact]]
name = "loom_concurrency"
kind = "loom"
command = "RUSTFLAGS='--cfg loom' cargo test -p chio-kernel --release --test loom_concurrency"
trust_boundary = "arc_swap::ArcSwap internals are not loom-instrumented; protocol around the cell is"

[[artifact]]
name = "dst_drop_simulation"
kind = "dst"
command = "cargo test -p chio-kernel --test dst_drop_simulation"
conformance = "cargo test -p chio-kernel --features sqlite-dst --test dst_drop_simulation"

[[artifact]]
name = "SessionCancel"
kind = "apalache"
invariants = ["NoDoubleOutcome", "HeldQuarantine", "HeldStickyAction"]
length = 8
```

Recap. The four concurrent objects of this wave are reduced to pure total step functions in a new `#![no_std]`, unsafe-free, checked-arithmetic core module, which the loom harness, the crash simulation, the Kani harnesses, and the Lean lemmas all share. Theorem 1 proves that any single-word CAS loop or single-mutex object over such a function is linearizable, and Theorem 2 transfers every sequentially proved invariant to every schedule, including the one a Tier-0 micro-model induces. The loom suite exercises cancel against both dispatch cutpoints, commit against rollback with a re-reserve to expose ABA, concurrent epoch publication with a torn-snapshot oracle, and sibling admission with destructor-driven holder release, each checked by a brute-force linearizer, and both planted mutations were caught. The deterministic simulation drops the process at every record boundary across sixty-four seeds and verifies prefix closure and the generation-tag lemma, with an optional real-WAL truncation conformance run. Remaining work is to land the `BudgetSplit::admit_child` call into the pure admission function and to add the manifest entries above so the pinned proofs stay green.

---

# Verbatim Treatise - `wave8_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_8`

I'll lay out the Wave 8 Angle 4 design as a treatise: the lift from the three protocol edges into `PortableToolCallRequest`, the hybrid signing floor, the federated offline verifier with hardware attestation, and the proof obligations that discharge once under the Envelope Preservation and Verification Transfer Theorem.

## 1. The lift: three protocol edges, one canonical request

**Where this sits in the law.** The protocol edges are the L3 instance of the canonical tuple. The exact computation at the edge is the offline receipt verifier plus the kernel `GuardPipeline`. The predictor is the Tier-1 `UltraBERT` for routing hints and the Tier-0 `FixedQ16_16` scorer on the hot path. The projection is a two-element envelope whose fallback is `Deny`. The witness is the hybrid-signed `PortableReceipt`. Nothing learned touches the verifier, and no exact predicate is ever delegated to a model. Each adapter extracts byte slices for the four Copley roles and hands them to a `#![no_std]` core that does every byte of canonicalization. Only the core is verified, so the adapters cannot change the meaning of a lifted request.

| Segment | MCP `tools/call` | A2A `tasks/send` | Envoy `CheckRequest` |
|---|---|---|---|
| `CommandLine` | RFC 8785 JCS of `params.arguments` | JCS of `message.parts` | `method SP path SP hex(H(body))` |
| `Image` | `params.name` | skill id | `destination.principal` |
| `OriginalFileName` | server name and version | remote `AgentCard` URL | `:authority` plus route name |
| `ParentImage` | client session principal | authenticated caller agent id | `source.principal` from mTLS |

The predicate index space of the Copley head is partitioned by segment through prefix sums, so the core can map any of the atomic predicates back to the role it reads from.

| Constant | Value |
|---|---|
| `SEGMENT_PREDICATE_COUNTS` | `[345, 97, 57, 38]` |
| `PREDICATE_OFFSETS` | `[0, 345, 442, 499, 537]` |
| `MAX_SEGMENT_BYTES` | `4096` |
| `MAX_CANONICAL_REQUEST_BYTES` | `16481` |
| `MAX_CROSS_CERT_DEPTH` | `3` |
| `MAX_TRUST_ROOTS` | `64` |

**The core crate.** This is `crates/edges/chio-protocol-edge-core/src/lib.rs`. It is strictly additive to the existing crates and mirrors two kernel functions by value so that it can stay dependency free. The mirrors are pinned to the kernel originals by Kani equivalence harnesses in section three.

```rust
//! crates/edges/chio-protocol-edge-core/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(u8)]
pub enum K3 { Pos = 0, Neg = 1, Unk = 2 }

impl K3 {
    pub const fn and(self, other: K3) -> K3 {
        match (self, other) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
            (K3::Pos, K3::Pos) => K3::Pos,
            _ => K3::Unk,
        }
    }
    pub const fn from_bool(b: bool) -> K3 { if b { K3::Pos } else { K3::Neg } }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EdgeProtocol { Mcp = 1, A2a = 2, EnvoyExtAuthz = 3 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CopleySegment { CommandLine = 0, Image = 1, OriginalFileName = 2, ParentImage = 3 }

pub const SEGMENT_COUNT: usize = 4;
pub const SEGMENT_ORDER: [CopleySegment; SEGMENT_COUNT] = [
    CopleySegment::CommandLine, CopleySegment::Image,
    CopleySegment::OriginalFileName, CopleySegment::ParentImage,
];
pub const SEGMENT_PREDICATE_COUNTS: [u16; SEGMENT_COUNT] = [345, 97, 57, 38];
pub const PREDICATE_OFFSETS: [u16; 5] = [0, 345, 442, 499, 537];
pub const TOTAL_ATOMIC_PREDICATES: u16 = 537;
pub const MAX_SEGMENT_BYTES: usize = 4096;
pub const LIFT_DOMAIN_TAG: [u8; 16] = *b"CHIO-PTCR-v1\0\0\0\0";
pub const MAX_CANONICAL_REQUEST_BYTES: usize =
    16 + 1 + SEGMENT_COUNT * (4 + MAX_SEGMENT_BYTES) + 32 + 8 * 4;

pub fn segment_of_predicate(j: u16) -> Option<CopleySegment> {
    if j >= TOTAL_ATOMIC_PREDICATES { return None; }
    SEGMENT_ORDER.iter().copied().zip(PREDICATE_OFFSETS.windows(2))
        .find(|(_, w)| w[0] <= j && j < w[1]).map(|(s, _)| s)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiftError { SegmentTooLong, Overflow, MissingRole(CopleySegment), InvalidWindow }

#[derive(Clone, Copy)]
pub struct Bounded<const N: usize> { buf: [u8; N], len: usize }

impl<const N: usize> Bounded<N> {
    pub const fn empty() -> Self { Self { buf: [0u8; N], len: 0 } }
    pub fn push_slice(&mut self, s: &[u8]) -> Result<(), LiftError> {
        let end = self.len.checked_add(s.len()).ok_or(LiftError::Overflow)?;
        if end > N { return Err(LiftError::SegmentTooLong); }
        self.buf[self.len..end].copy_from_slice(s);
        self.len = end;
        Ok(())
    }
    pub fn push_u32_le(&mut self, v: u32) -> Result<(), LiftError> { self.push_slice(&v.to_le_bytes()) }
    pub fn push_u64_le(&mut self, v: u64) -> Result<(), LiftError> { self.push_slice(&v.to_le_bytes()) }
    pub fn as_slice(&self) -> &[u8] { &self.buf[..self.len] }
    pub const fn len(&self) -> usize { self.len }
}

/// What an adapter hands the core: one byte slice per Copley role.
pub struct RawEdgeCall<'a> {
    pub protocol: EdgeProtocol,
    pub roles: [&'a [u8]; SEGMENT_COUNT],
    pub body_digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub invocation_cost: u64,
    pub unit_cost: u64,
}

#[derive(Clone, Copy)]
pub struct PortableToolCallRequest {
    pub protocol: EdgeProtocol,
    pub segments: [Bounded<MAX_SEGMENT_BYTES>; SEGMENT_COUNT],
    pub body_digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub invocation_cost: u64,
    pub unit_cost: u64,
}

impl PortableToolCallRequest {
    pub fn lift(raw: &RawEdgeCall<'_>) -> Result<Self, LiftError> {
        if raw.expires_at <= raw.issued_at { return Err(LiftError::InvalidWindow); }
        let mut segments = [Bounded::<MAX_SEGMENT_BYTES>::empty(); SEGMENT_COUNT];
        for (idx, (seg, role)) in segments.iter_mut().zip(raw.roles).enumerate() {
            if role.is_empty() { return Err(LiftError::MissingRole(SEGMENT_ORDER[idx])); }
            seg.push_slice(role)?;
        }
        Ok(Self {
            protocol: raw.protocol, segments, body_digest: raw.body_digest,
            issued_at: raw.issued_at, expires_at: raw.expires_at,
            invocation_cost: raw.invocation_cost, unit_cost: raw.unit_cost,
        })
    }

    /// Injective, length-prefixed canonical form (Theorem T3).
    pub fn canonical_bytes(&self) -> Result<Bounded<MAX_CANONICAL_REQUEST_BYTES>, LiftError> {
        let mut out = Bounded::empty();
        out.push_slice(&LIFT_DOMAIN_TAG)?;
        out.push_slice(&[self.protocol as u8])?;
        for seg in &self.segments {
            let n = u32::try_from(seg.len()).map_err(|_| LiftError::Overflow)?;
            out.push_u32_le(n)?;
            out.push_slice(seg.as_slice())?;
        }
        out.push_slice(&self.body_digest)?;
        out.push_u64_le(self.issued_at)?;
        out.push_u64_le(self.expires_at)?;
        out.push_u64_le(self.invocation_cost)?;
        out.push_u64_le(self.unit_cost)?;
        Ok(out)
    }
}

/// Mirror of `formal_core::classify_time_window_code`; pinned by Kani equivalence.
pub fn classify_time_window_code(now: u64, issued_at: u64, expires_at: u64) -> u8 {
    if now < issued_at { 1 } else if expires_at <= now { 2 } else { 0 }
}

/// Mirror of `formal_aeneas::receipt_fields_coupled`; pinned by Kani equivalence.
pub fn receipt_fields_coupled(c: bool, r: bool, v: bool, p: bool, e: bool) -> bool { c & r & v & p & e }
```

**Tier-0 scoring and role-asymmetric thresholds.** The hot-path scorer applies the shadow-price vector as a Lagrangian penalty in fixed point. Any overflow returns `None`, and the projection treats `None` as a score below threshold. An arithmetic failure is therefore a `Deny`, never a panic. The predicate mapping respects the invariant that the negative threshold never exceeds the positive one, so no predicate can be both affirmed and refuted.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedQ16_16(pub i32);

impl FixedQ16_16 {
    pub const ONE: Self = Self(1 << 16);
    pub fn checked_add(self, o: Self) -> Option<Self> { self.0.checked_add(o.0).map(Self) }
    pub fn checked_sub(self, o: Self) -> Option<Self> { self.0.checked_sub(o.0).map(Self) }
    pub fn checked_mul(self, o: Self) -> Option<Self> {
        let wide = i64::from(self.0).checked_mul(i64::from(o.0))?;
        i32::try_from(wide.checked_shr(16)?).ok().map(Self)
    }
}

#[derive(Clone, Copy)]
pub struct ShadowPrices { pub budget: FixedQ16_16, pub fuel: FixedQ16_16, pub latency: FixedQ16_16, pub memory: FixedQ16_16, pub escrow: FixedQ16_16 }
#[derive(Clone, Copy)]
pub struct ResourceUse { pub budget: FixedQ16_16, pub fuel: FixedQ16_16, pub latency: FixedQ16_16, pub memory: FixedQ16_16, pub escrow: FixedQ16_16 }

pub fn tier0_score(raw: FixedQ16_16, lambda: &ShadowPrices, use_: &ResourceUse) -> Option<FixedQ16_16> {
    let penalty = lambda.budget.checked_mul(use_.budget)?
        .checked_add(lambda.fuel.checked_mul(use_.fuel)?)?
        .checked_add(lambda.latency.checked_mul(use_.latency)?)?
        .checked_add(lambda.memory.checked_mul(use_.memory)?)?
        .checked_add(lambda.escrow.checked_mul(use_.escrow)?)?;
    raw.checked_sub(penalty)
}

pub fn predicate_k3(p: FixedQ16_16, tau_pos: FixedQ16_16, tau_neg: FixedQ16_16) -> Option<K3> {
    if tau_neg > tau_pos { return None; }
    Some(if p >= tau_pos { K3::Pos } else if p <= tau_neg { K3::Neg } else { K3::Unk })
}
```

**The adapters.** Each adapter is a thin `std` crate that parses its wire format and builds a `RawEdgeCall`. The MCP edge is representative. The A2A adapter differs only in the role sources from the table above, and the Envoy adapter reads the prost-generated `CheckRequest` attributes. All three call `PortableToolCallRequest::lift`, hash the canonical bytes, and then run the kernel `GuardPipeline` unchanged.

```rust
//! crates/edges/chio-mcp-edge/src/lift.rs
use chio_protocol_edge_core::{Digest32, EdgeProtocol, LiftError, PortableToolCallRequest, RawEdgeCall};
use serde_json::Value;

pub struct McpLiftContext<'a> {
    pub server_identity: &'a str,
    pub client_session: &'a str,
    pub now: u64,
    pub ttl: u64,
    pub invocation_cost: u64,
    pub unit_cost: u64,
}

#[derive(Debug)]
pub enum McpLiftError { MissingName, Canonical(serde_json::Error), Overflow, Lift(LiftError) }

pub fn lift_tools_call<H: Digest32>(params: &Value, ctx: &McpLiftContext<'_>) -> Result<PortableToolCallRequest, McpLiftError> {
    let name = params.get("name").and_then(Value::as_str).ok_or(McpLiftError::MissingName)?;
    let args = params.get("arguments").cloned().unwrap_or_else(|| Value::Object(Default::default()));
    let canonical_args = serde_jcs::to_vec(&args).map_err(McpLiftError::Canonical)?;
    let expires_at = ctx.now.checked_add(ctx.ttl).ok_or(McpLiftError::Overflow)?;
    let raw = RawEdgeCall {
        protocol: EdgeProtocol::Mcp,
        roles: [&canonical_args, name.as_bytes(), ctx.server_identity.as_bytes(), ctx.client_session.as_bytes()],
        body_digest: H::digest(&canonical_args),
        issued_at: ctx.now,
        expires_at,
        invocation_cost: ctx.invocation_cost,
        unit_cost: ctx.unit_cost,
    };
    PortableToolCallRequest::lift(&raw).map_err(McpLiftError::Lift)
}
```

```rust
//! crates/edges/chio-envoy-ext-authz/src/lift.rs (excerpt)
pub fn lift_check_request<H: Digest32>(req: &CheckRequest, now: u64, ttl: u64) -> Result<PortableToolCallRequest, EnvoyLiftError> {
    let attrs = req.attributes.as_ref().ok_or(EnvoyLiftError::MissingAttributes)?;
    let http = attrs.request.as_ref().and_then(|r| r.http.as_ref()).ok_or(EnvoyLiftError::MissingHttp)?;
    let source = attrs.source.as_ref().map(|p| p.principal.as_str()).unwrap_or("");
    let destination = attrs.destination.as_ref().map(|p| p.principal.as_str()).unwrap_or("");
    let authority = http.headers.get(":authority").map(String::as_str).unwrap_or("");
    let body_digest = H::digest(http.body.as_bytes());
    let command_line = format!("{} {} {}", http.method, http.path, hex::encode(body_digest));
    let origin = format!("{}/{}", authority, attrs.context_extensions.get("route").map(String::as_str).unwrap_or(""));
    let expires_at = now.checked_add(ttl).ok_or(EnvoyLiftError::Overflow)?;
    let raw = RawEdgeCall {
        protocol: EdgeProtocol::EnvoyExtAuthz,
        roles: [command_line.as_bytes(), destination.as_bytes(), origin.as_bytes(), source.as_bytes()],
        body_digest, issued_at: now, expires_at, invocation_cost: 1, unit_cost: 1,
    };
    PortableToolCallRequest::lift(&raw).map_err(EnvoyLiftError::Lift)
}
```

**Kernel coupling.** Before Tier-1 runs, the edge calls `budget_precheck` with the lifted costs and reserves on the ledger with `ledger_apply` using op code zero. On `Allow` it commits with op code one and requires `BudgetCommitResult.accepted` before a receipt may carry an `Allow` verdict. On `Deny` it releases with op code two. The `GuardPipeline` semantics are preserved exactly: `PendingApproval` is sticky, a later `Deny` still wins, and a guard error is a `Deny` with evidence. The mapping back to the wire is fixed.

| Kernel verdict | MCP | A2A | Envoy |
|---|---|---|---|
| `Allow` | result with receipt in `_meta` | task `completed` with receipt artifact | `OkHttpResponse` plus receipt header |
| `Deny` | JSON-RPC error, code `-32001` | task `rejected` | `DeniedHttpResponse`, status `403` |
| `PendingApproval` | JSON-RPC error, code `-32002`, retryable | task `auth-required` | status `403` with pending and retry headers |

Long-running A2A tasks are revalidated through `revalidate_before_dispatch` when `requires_dispatch_revalidation` is set, so a stale `Allow` cannot be redeemed after policy changes.

## 2. KernelCryptoFloor: hybrid Ed25519 plus ML-DSA-65 receipts and federated offline verification

**Design rule.** A receipt is a portable, offline-verifiable witness. The verifier may run years later, on another organization's hardware, with no network. So the floor is a signed field, both signature components must verify, and every byte the signer commits to is reproducible from the request alone. The `KernelCryptoFloor` trait bundles the three primitives and the attestation verifier, and the floor constant is the deployment policy, not a runtime knob.

```rust
pub const ED25519_PK_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const MLDSA65_PK_LEN: usize = 1952;
pub const MLDSA65_SIG_LEN: usize = 3309;
pub const HYBRID_PK_LEN: usize = ED25519_PK_LEN + MLDSA65_PK_LEN;
pub const RECEIPT_DOMAIN_TAG: [u8; 16] = *b"CHIO-RCPT-v1\0\0\0\0";
pub const COMPOSITE_CTX: [u8; 27] = *b"CHIO-HYBRID-ED25519-MLDSA65";
pub const MAX_CANONICAL_RECEIPT_BYTES: usize = 16 + 1 + 32 + 32 + 32 + 1 + 32 + 1 + 8 + 8 + 32 + 32;
pub const MAX_COMPOSITE_BYTES: usize = 27 + MAX_CANONICAL_RECEIPT_BYTES;
pub const MAX_CROSS_CERT_BYTES: usize = 27 + 16 + 32 + HYBRID_PK_LEN + 1 + 32 + 8 + 8;

pub trait Digest32 { fn digest(data: &[u8]) -> [u8; 32]; }
pub trait Ed25519Verify { fn verify(pk: &[u8; ED25519_PK_LEN], msg: &[u8], sig: &[u8; ED25519_SIG_LEN]) -> bool; }
pub trait MlDsa65Verify { fn verify(pk: &[u8; MLDSA65_PK_LEN], msg: &[u8], ctx: &[u8], sig: &[u8; MLDSA65_SIG_LEN]) -> bool; }
pub trait AttestationVerifier { fn verify_quote(evidence: &AttestationEvidence, raw_quote: &[u8]) -> K3; }

pub trait KernelCryptoFloor {
    type Hash: Digest32;
    type Ed: Ed25519Verify;
    type Ml: MlDsa65Verify;
    type Att: AttestationVerifier;
    const FLOOR: CryptoFloor;
}

/// Signing side, implemented by the kernel with hardware-resident keys.
pub trait HybridSigner {
    fn floor(&self) -> CryptoFloor;
    fn sign(&self, composite_input: &[u8]) -> Result<ReceiptSignature, SignError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError { KeyUnavailable, BelowFloor, Backend }

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CryptoFloor { Ed25519Only = 1, HybridEd25519MlDsa65 = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict { Allow = 0, Deny = 1, PendingApproval = 2 }

#[derive(Clone, Copy)]
pub struct HybridPublicKey { pub ed25519: [u8; ED25519_PK_LEN], pub mldsa65: [u8; MLDSA65_PK_LEN] }

#[derive(Clone, Copy)]
pub enum ReceiptSignature {
    Ed25519Only([u8; ED25519_SIG_LEN]),
    Hybrid { ed25519: [u8; ED25519_SIG_LEN], mldsa65: [u8; MLDSA65_SIG_LEN] },
}

impl ReceiptSignature {
    pub const fn claimed_floor(&self) -> CryptoFloor {
        match self {
            Self::Ed25519Only(_) => CryptoFloor::Ed25519Only,
            Self::Hybrid { .. } => CryptoFloor::HybridEd25519MlDsa65,
        }
    }
}

/// AND-composition with a shared domain-separated input (Theorems T1, T2).
pub fn verify_signature<F: KernelCryptoFloor>(key: &HybridPublicKey, required_floor: CryptoFloor, composite: &[u8], sig: &ReceiptSignature) -> bool {
    let claimed = sig.claimed_floor();
    if claimed < required_floor || claimed < F::FLOOR { return false; }
    match sig {
        ReceiptSignature::Ed25519Only(ed) => F::Ed::verify(&key.ed25519, composite, ed),
        ReceiptSignature::Hybrid { ed25519, mldsa65 } => {
            let ed_ok = F::Ed::verify(&key.ed25519, composite, ed25519);
            let ml_ok = F::Ml::verify(&key.mldsa65, composite, &COMPOSITE_CTX, mldsa65);
            ed_ok & ml_ok
        }
    }
}

pub fn hybrid_key_hash<F: KernelCryptoFloor>(key: &HybridPublicKey) -> [u8; 32] {
    let mut buf = [0u8; HYBRID_PK_LEN];
    buf[..ED25519_PK_LEN].copy_from_slice(&key.ed25519);
    buf[ED25519_PK_LEN..].copy_from_slice(&key.mldsa65);
    F::Hash::digest(&buf)
}
```

**The receipt.** Every field below the signature is part of the signing input, including the floor, the attestation hash, and the hash of the Tier-1 weights that produced the advisory. The weights hash comes from `LoadedWeights::loaded_weights_hash` after `evaluate_weights_binding` has accepted the model card. It is accountability data, not a safety dependency.

```rust
#[derive(Clone, Copy)]
pub struct PortableReceipt {
    pub issuer_root_id: [u8; 32],
    pub floor: CryptoFloor,
    pub request_hash: [u8; 32],
    pub capability_hash: [u8; 32],
    pub verdict: Verdict,
    pub policy_hash: [u8; 32],
    pub evidence_class: u8,
    pub issued_at: u64,
    pub expires_at: u64,
    pub attestation_hash: [u8; 32],
    pub weights_hash: [u8; 32],
    pub signature: ReceiptSignature,
}

impl PortableReceipt {
    pub fn signing_input(&self) -> Result<Bounded<MAX_COMPOSITE_BYTES>, LiftError> {
        let mut out = Bounded::empty();
        out.push_slice(&COMPOSITE_CTX)?;
        out.push_slice(&RECEIPT_DOMAIN_TAG)?;
        out.push_slice(&[self.floor as u8])?;
        out.push_slice(&self.issuer_root_id)?;
        out.push_slice(&self.request_hash)?;
        out.push_slice(&self.capability_hash)?;
        out.push_slice(&[self.verdict as u8])?;
        out.push_slice(&self.policy_hash)?;
        out.push_slice(&[self.evidence_class])?;
        out.push_u64_le(self.issued_at)?;
        out.push_u64_le(self.expires_at)?;
        out.push_slice(&self.attestation_hash)?;
        out.push_slice(&self.weights_hash)?;
        Ok(out)
    }
}

pub fn request_hash<F: KernelCryptoFloor>(req: &PortableToolCallRequest) -> Result<[u8; 32], LiftError> {
    Ok(F::Hash::digest(req.canonical_bytes()?.as_slice()))
}
```

**Federated trust roots and cross-certification.** Each organization's kernel is a root. A verifier holds a bounded slice of roots it trusts directly. A partner root can be reached through a bounded chain of cross-certificates, each signed by the next root up the chain. Resolution walks subject to issuer until it hits a direct root, then verifies signatures from the anchor downward, inheriting the anchor's attestation policy.

```rust
pub const MAX_TRUST_ROOTS: usize = 64;
pub const MAX_PINNED_MEASUREMENTS: usize = 8;
pub const MAX_CROSS_CERT_DEPTH: usize = 3;

#[derive(Clone, Copy)]
pub struct TrustRoot {
    pub root_id: [u8; 32],
    pub public_key: HybridPublicKey,
    pub not_before: u64,
    pub not_after: u64,
    pub min_floor: CryptoFloor,
    pub attestation_required: bool,
    pub pinned_measurements: [[u8; 48]; MAX_PINNED_MEASUREMENTS],
    pub pinned_count: usize,
}

#[derive(Clone, Copy)]
pub struct RootCrossCert {
    pub subject_root_id: [u8; 32],
    pub subject_key: HybridPublicKey,
    pub subject_min_floor: CryptoFloor,
    pub issuer_root_id: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub signature: ReceiptSignature,
}

impl RootCrossCert {
    pub fn signing_input(&self) -> Result<Bounded<MAX_CROSS_CERT_BYTES>, LiftError> {
        let mut out = Bounded::empty();
        out.push_slice(&COMPOSITE_CTX)?;
        out.push_slice(b"CHIO-XCERT-v1\0\0\0")?;
        out.push_slice(&self.subject_root_id)?;
        out.push_slice(&self.subject_key.ed25519)?;
        out.push_slice(&self.subject_key.mldsa65)?;
        out.push_slice(&[self.subject_min_floor as u8])?;
        out.push_slice(&self.issuer_root_id)?;
        out.push_u64_le(self.not_before)?;
        out.push_u64_le(self.not_after)?;
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError { TooManyRoots, DuplicateRootId, BadPinnedCount }

pub struct FederatedTrustStore<'a> { roots: &'a [TrustRoot] }

impl<'a> FederatedTrustStore<'a> {
    pub fn new(roots: &'a [TrustRoot]) -> Result<Self, StoreError> {
        if roots.len() > MAX_TRUST_ROOTS { return Err(StoreError::TooManyRoots); }
        for (i, r) in roots.iter().enumerate() {
            if r.pinned_count > MAX_PINNED_MEASUREMENTS { return Err(StoreError::BadPinnedCount); }
            if roots[..i].iter().any(|p| p.root_id == r.root_id) { return Err(StoreError::DuplicateRootId); }
        }
        Ok(Self { roots })
    }
    pub fn find(&self, root_id: &[u8; 32]) -> Option<&'a TrustRoot> {
        self.roots.iter().find(|r| &r.root_id == root_id)
    }
}

pub struct ResolvedIssuer<'a> {
    pub key: HybridPublicKey,
    pub min_floor: CryptoFloor,
    pub not_before: u64,
    pub not_after: u64,
    pub anchor: &'a TrustRoot,
}

fn resolve_issuer<'a, F: KernelCryptoFloor>(store: &FederatedTrustStore<'a>, cross: &[RootCrossCert], issuer: &[u8; 32], now: u64) -> Option<ResolvedIssuer<'a>> {
    if let Some(root) = store.find(issuer) {
        return Some(ResolvedIssuer { key: root.public_key, min_floor: root.min_floor, not_before: root.not_before, not_after: root.not_after, anchor: root });
    }
    let mut chain: [Option<&RootCrossCert>; MAX_CROSS_CERT_DEPTH] = [None; MAX_CROSS_CERT_DEPTH];
    let mut current = *issuer;
    let mut depth = 0usize;
    let anchor = loop {
        if depth >= MAX_CROSS_CERT_DEPTH { return None; }
        let cert = cross.iter().find(|c| c.subject_root_id == current)?;
        if classify_time_window_code(now, cert.not_before, cert.not_after) != 0 { return None; }
        chain[depth] = Some(cert);
        depth = depth.checked_add(1)?;
        if let Some(root) = store.find(&cert.issuer_root_id) { break root; }
        current = cert.issuer_root_id;
    };
    let mut key = anchor.public_key;
    let mut floor = anchor.min_floor;
    let mut k = depth;
    while k > 0 {
        k = k.checked_sub(1)?;
        let cert = chain[k]?;
        let input = cert.signing_input().ok()?;
        if !verify_signature::<F>(&key, floor, input.as_slice(), &cert.signature) { return None; }
        key = cert.subject_key;
        floor = cert.subject_min_floor;
    }
    let leaf = chain[0]?;
    Some(ResolvedIssuer { key, min_floor: floor, not_before: leaf.not_before, not_after: leaf.not_after, anchor })
}
```

**Hardware attestation, pass eight.** Evidence binds the signing key to a measured platform. The evidence hash is in the signed receipt. The verifier checks the binding and the pinned measurement exactly, then asks the attestation backend about the vendor quote. An offline verifier without the vendor chain returns `Unk`, which the envelope treats as infeasible for `Allow`. This is the honest use of the third truth value: the verifier knows that it does not know.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AttestationKind { Tpm2Quote = 1, SgxDcap = 2, TdxQuote = 3, AppleSecureEnclave = 4 }

#[derive(Clone, Copy)]
pub struct AttestationEvidence {
    pub kind: AttestationKind,
    pub measurement: [u8; 48],
    pub signer_key_hash: [u8; 32],
    pub nonce: [u8; 32],
}

impl AttestationEvidence {
    pub fn canonical_bytes(&self) -> [u8; 113] {
        let mut out = [0u8; 113];
        out[0] = self.kind as u8;
        out[1..49].copy_from_slice(&self.measurement);
        out[49..81].copy_from_slice(&self.signer_key_hash);
        out[81..113].copy_from_slice(&self.nonce);
        out
    }
}

fn attestation_verdict<F: KernelCryptoFloor>(anchor: &TrustRoot, issuer_key: &HybridPublicKey, receipt: &PortableReceipt, evidence: Option<(&AttestationEvidence, &[u8])>) -> K3 {
    if !anchor.attestation_required { return K3::Pos; }
    let Some((ev, raw)) = evidence else { return K3::Neg; };
    let bound = F::Hash::digest(&ev.canonical_bytes()) == receipt.attestation_hash;
    let key_bound = ev.signer_key_hash == hybrid_key_hash::<F>(issuer_key);
    let pinned = anchor.pinned_measurements.get(..anchor.pinned_count).unwrap_or(&[]);
    let measured = pinned.iter().any(|m| *m == ev.measurement);
    K3::from_bool(bound & key_bound & measured).and(F::Att::verify_quote(ev, raw))
}
```

**The verifier and the envelope.** The verifier is the exact computation. It returns a three-valued verdict with a reason, and it is the only place that can construct an `Envelope`. The projection admits `Allow` only when the verdict is `Pos`, the receipt itself says `Allow`, and the Tier-0 score clears its threshold. Everything else, including an arithmetic failure in the scorer, projects to the fallback.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyReason { Ok, ReceiptWindow(u8), UnknownIssuer, IssuerWindow(u8), FloorMismatch, FloorBelowPolicy, Encoding, BadSignature, FieldsUncoupled, Attestation(K3) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfflineVerdict { pub verified: K3, pub reason: VerifyReason }

#[derive(Clone, Copy)]
pub struct ExpectedCoupling { pub capability_hash: [u8; 32], pub request_hash: [u8; 32], pub verdict: Verdict, pub policy_hash: [u8; 32], pub evidence_class: u8 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EdgeAction { Allow = 0, Deny = 1 }

/// Private field: only `verify_offline` can construct one.
#[derive(Clone, Copy)]
pub struct Envelope { allow_feasible: bool }

impl Envelope {
    pub const fn fallback(&self) -> EdgeAction { EdgeAction::Deny }
    pub fn project(&self, score: Option<FixedQ16_16>, tau: FixedQ16_16) -> EdgeAction {
        match score {
            Some(s) if self.allow_feasible && s >= tau => EdgeAction::Allow,
            _ => EdgeAction::Deny,
        }
    }
}

pub struct Admission { pub verdict: OfflineVerdict, pub envelope: Envelope }

const fn neg(reason: VerifyReason) -> OfflineVerdict { OfflineVerdict { verified: K3::Neg, reason } }

pub fn verify_offline<F: KernelCryptoFloor>(store: &FederatedTrustStore<'_>, cross: &[RootCrossCert], receipt: &PortableReceipt, expected: &ExpectedCoupling, evidence: Option<(&AttestationEvidence, &[u8])>, now: u64) -> Admission {
    let verdict = verify_inner::<F>(store, cross, receipt, expected, evidence, now);
    let allow_feasible = verdict.verified == K3::Pos && receipt.verdict == Verdict::Allow;
    Admission { verdict, envelope: Envelope { allow_feasible } }
}

fn verify_inner<F: KernelCryptoFloor>(store: &FederatedTrustStore<'_>, cross: &[RootCrossCert], receipt: &PortableReceipt, expected: &ExpectedCoupling, evidence: Option<(&AttestationEvidence, &[u8])>, now: u64) -> OfflineVerdict {
    let w = classify_time_window_code(now, receipt.issued_at, receipt.expires_at);
    if w != 0 { return neg(VerifyReason::ReceiptWindow(w)); }
    let Some(issuer) = resolve_issuer::<F>(store, cross, &receipt.issuer_root_id, now) else {
        return OfflineVerdict { verified: K3::Unk, reason: VerifyReason::UnknownIssuer };
    };
    let iw = classify_time_window_code(now, issuer.not_before, issuer.not_after);
    if iw != 0 { return neg(VerifyReason::IssuerWindow(iw)); }
    if receipt.floor != receipt.signature.claimed_floor() { return neg(VerifyReason::FloorMismatch); }
    if receipt.floor < issuer.min_floor || receipt.floor < F::FLOOR { return neg(VerifyReason::FloorBelowPolicy); }
    let Ok(input) = receipt.signing_input() else { return neg(VerifyReason::Encoding); };
    if !verify_signature::<F>(&issuer.key, issuer.min_floor, input.as_slice(), &receipt.signature) {
        return neg(VerifyReason::BadSignature);
    }
    let coupled = receipt_fields_coupled(
        receipt.capability_hash == expected.capability_hash,
        receipt.request_hash == expected.request_hash,
        receipt.verdict == expected.verdict,
        receipt.policy_hash == expected.policy_hash,
        receipt.evidence_class == expected.evidence_class,
    );
    if !coupled { return neg(VerifyReason::FieldsUncoupled); }
    match attestation_verdict::<F>(issuer.anchor, &issuer.key, receipt, evidence) {
        K3::Pos => OfflineVerdict { verified: K3::Pos, reason: VerifyReason::Ok },
        other => OfflineVerdict { verified: other, reason: VerifyReason::Attestation(other) },
    }
}
```

**Additivity.** Nothing in the pinned kernel changes. The reserved metadata array keeps its length, and the edge adds two keys through a companion constant and a predicate that checks both arrays. This keeps `formal/proof-manifest.toml` and the Lean modules under `formal/lean4/Chio/` untouched.

```rust
//! crates/core/chio-core-types/src/receipt/metadata.rs (additive)
pub const PROTOCOL_EDGE_METADATA_KEYS: [&str; 2] = ["protocol_edge_lift", "signer_attestation"];
pub fn is_reserved_receipt_metadata_key(key: &str) -> bool {
    RESERVED_RECEIPT_METADATA_KEYS.contains(&key) || PROTOCOL_EDGE_METADATA_KEYS.contains(&key)
}
```

## 3. Proof obligations: the mathematics, Lean 4, Kani, and Apalache

**Theorem T1, AND-composite unforgeability.** Let the composite scheme sign a message by producing an Ed25519 signature and an ML-DSA-65 signature over the same domain-separated input, and accept only if both verify. If either component is EUF-CMA secure, the composite is EUF-CMA secure with the same advantage bound. Proof. Let a forger produce a fresh message with a composite signature that verifies. Build a reduction against component one. The reduction generates the key pair for component two itself, forwards the component one public key, answers each signing query by calling its own oracle for component one and signing locally with component two, and outputs the component one part of the forgery. Because the composite verifies only if both parts verify, the forwarded part is a valid component one forgery on a message never queried. The advantage is preserved exactly. The symmetric reduction holds for component two. Hence the composite is at least as strong as the stronger component, which is the hybrid guarantee the floor relies on.

**Theorem T2, downgrade resistance.** No adversary can convert a hybrid receipt into an accepted single-component receipt without forging Ed25519. Proof. The floor byte and the issuer id are inside the signing input. A stripped receipt must carry the `Ed25519Only` variant to pass the variant check, so its declared floor must be `Ed25519Only`, which changes the signed bytes. The adversary then needs a valid Ed25519 signature on a message the honest signer never signed. If the issuer's minimum floor or the verifier's deployment floor is hybrid, the stripped receipt is rejected before any signature check by the floor comparison. Both branches are visible in `verify_signature` and `verify_inner`.

**Theorem T3, canonical encoding injectivity.** The map from `PortableToolCallRequest` to canonical bytes is injective. Proof. The output begins with a fixed-width tag and a fixed-width protocol byte, so these parse uniquely. Each segment is a four-byte little-endian length followed by exactly that many bytes, so by induction on the segment index the boundary of each segment is determined by the prefix before it, and two encodings agreeing on the full output agree on every segment length and content. The trailing digest and four integers are fixed width. Two requests with equal encodings therefore have equal fields. The same argument applies to the receipt and cross-certificate signing inputs, which are entirely fixed width.

**Theorem T4, soundness and conservativeness of offline verification.** The verifier returns `Pos` only when the receipt window is valid now, the issuer resolves to a directly trusted root through a chain of at most the maximum depth with every link verifying under its parent key, the issuer window is valid, the declared floor equals the signature variant and dominates both policy floors, the hybrid signature verifies, all five receipt fields are coupled, and attestation is positive. Proof is by inspection of the straight-line control flow: every early return yields `Neg` or `Unk`, and the only `Pos` return follows the last check. Conservativeness: the envelope's `allow_feasible` is a conjunction containing `verified == Pos`, so any `Neg` or `Unk` makes `Allow` infeasible and the projection returns the fallback regardless of the learned score.

**Theorem T5, envelope preservation and verification transfer at the edge.** Replace the Tier-0 score and threshold by an arbitrary boolean. The set of reachable actions is unchanged, because the projection already quantifies over all scores. Hence every property proved with the learned choice modeled as nondeterminism holds for any trained model, and a model update never reopens a proof. This is exactly the discharge-once rule from Wave 1 and is what the Kani and TLA+ artifacts below exploit.

**Lean 4.** The module lives under `formal/lean4/Chio/ProtocolEdge.lean` and is additive.

```lean
namespace Chio.ProtocolEdge

inductive K3 | pos | neg | unk
deriving DecidableEq, Repr

def K3.and : K3 → K3 → K3
  | .neg, _ => .neg
  | _, .neg => .neg
  | .pos, .pos => .pos
  | _, _ => .unk

theorem K3.and_pos_iff (a b : K3) : a.and b = .pos ↔ a = .pos ∧ b = .pos := by
  cases a <;> cases b <;> decide

theorem K3.and_neg_absorb (a : K3) : K3.neg.and a = .neg := by
  cases a <;> rfl

/-- Mirror of `classify_time_window_code`: 0 valid, 1 not yet valid, 2 expired. -/
def classifyTimeWindowCode (now issuedAt expiresAt : Nat) : Nat :=
  if now < issuedAt then 1 else if expiresAt ≤ now then 2 else 0

theorem classify_valid_iff (now i e : Nat) :
    classifyTimeWindowCode now i e = 0 ↔ i ≤ now ∧ now < e := by
  unfold classifyTimeWindowCode
  split <;> (try split) <;> constructor <;> intro h <;> omega

structure HybridSig where
  ed : List UInt8
  ml : List UInt8

def verifyHybrid (ved vml : List UInt8 → List UInt8 → Bool) (m : List UInt8) (σ : HybridSig) : Bool :=
  ved m σ.ed && vml m σ.ml

theorem verifyHybrid_sound (ved vml : List UInt8 → List UInt8 → Bool) (m : List UInt8) (σ : HybridSig) :
    verifyHybrid ved vml m σ = true → ved m σ.ed = true ∧ vml m σ.ml = true := by
  intro h
  simpa [verifyHybrid, Bool.and_eq_true] using h

inductive Floor | ed25519Only | hybrid
deriving DecidableEq

def Floor.rank : Floor → Nat
  | .ed25519Only => 1
  | .hybrid => 2

def floorOk (claimed policy deploy : Floor) : Bool :=
  policy.rank ≤ claimed.rank && deploy.rank ≤ claimed.rank

theorem floorOk_hybrid_universal (p d : Floor) : floorOk .hybrid p d = true := by
  cases p <;> cases d <;> decide

theorem floorOk_edOnly_rejected_under_hybrid_policy (d : Floor) :
    floorOk .ed25519Only .hybrid d = false := by
  cases d <;> decide

inductive Action | allow | deny
deriving DecidableEq

def project (verified : K3) (receiptAllow learned : Bool) : Action :=
  if verified = .pos ∧ receiptAllow = true then (if learned then .allow else .deny) else .deny

theorem project_deny_unless_pos (v : K3) (r l : Bool) (h : v ≠ .pos) : project v r l = .deny := by
  simp [project, h]

theorem project_learned_irrelevant_when_infeasible (v : K3) (r l₁ l₂ : Bool) (h : v ≠ .pos) :
    project v r l₁ = project v r l₂ := by
  simp [project, h]

end Chio.ProtocolEdge
```

The Aeneas side extracts `classify_time_window_code`, `receipt_fields_coupled`, `predicate_k3`, and `tier0_score` from the core crate. All four are pure, value-passing functions in the same style as `ledger_apply`, and `Bounded::push_slice` extracts with a backward function for its single mutable borrow. Their extracted definitions are proved equal to the Lean mirrors above by `rfl` after unfolding, which is what pins the Rust to the specification.

**Kani.** The harnesses live in `verify/kani/protocol_edge.rs` and compile the core crate together with `chio-kernel-core`, so the equivalence harnesses call both implementations.

```rust
#[cfg(kani)]
mod harness {
    use chio_protocol_edge_core::*;

    struct MockHash;
    impl Digest32 for MockHash { fn digest(_: &[u8]) -> [u8; 32] { [0u8; 32] } }
    struct MockEd;
    impl Ed25519Verify for MockEd { fn verify(_: &[u8; 32], _: &[u8], sig: &[u8; 64]) -> bool { sig[0] == 1 } }
    struct MockMl;
    impl MlDsa65Verify for MockMl { fn verify(_: &[u8; 1952], _: &[u8], _: &[u8], sig: &[u8; 3309]) -> bool { sig[0] == 1 } }
    struct MockAtt;
    impl AttestationVerifier for MockAtt { fn verify_quote(_: &AttestationEvidence, _: &[u8]) -> K3 { K3::Pos } }
    struct Floor;
    impl KernelCryptoFloor for Floor {
        type Hash = MockHash; type Ed = MockEd; type Ml = MockMl; type Att = MockAtt;
        const FLOOR: CryptoFloor = CryptoFloor::HybridEd25519MlDsa65;
    }

    #[kani::proof]
    fn time_window_mirror_matches_kernel_core() {
        let (now, i, e): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        assert_eq!(classify_time_window_code(now, i, e),
                   chio_kernel_core::formal_core::classify_time_window_code(now, i, e));
    }

    #[kani::proof]
    fn coupling_mirror_matches_kernel_core() {
        let v: [bool; 5] = kani::any();
        assert_eq!(receipt_fields_coupled(v[0], v[1], v[2], v[3], v[4]),
                   chio_kernel_core::formal_aeneas::receipt_fields_coupled(v[0], v[1], v[2], v[3], v[4]));
    }

    #[kani::proof]
    fn k3_and_is_kleene_meet() {
        let (a, b): (K3, K3) = (kani::any(), kani::any());
        assert_eq!(a.and(b), b.and(a));
        assert_eq!(a.and(b) == K3::Pos, a == K3::Pos && b == K3::Pos);
        assert_eq!(K3::Neg.and(a), K3::Neg);
    }

    #[kani::proof]
    fn bounded_push_never_panics_and_respects_capacity() {
        let mut b = Bounded::<8>::empty();
        let n: usize = kani::any();
        kani::assume(n <= 16);
        let src = [0xA5u8; 16];
        let r = b.push_slice(&src[..n]);
        assert!(b.len() <= 8);
        assert_eq!(r.is_ok(), n <= 8);
    }

    #[kani::proof]
    fn hybrid_verification_is_conjunction() {
        let key = HybridPublicKey { ed25519: [0u8; 32], mldsa65: [0u8; 1952] };
        let mut ed = [0u8; 64];
        let mut ml = [0u8; 3309];
        ed[0] = kani::any();
        ml[0] = kani::any();
        let sig = ReceiptSignature::Hybrid { ed25519: ed, mldsa65: ml };
        let ok = verify_signature::<Floor>(&key, CryptoFloor::HybridEd25519MlDsa65, b"m", &sig);
        assert_eq!(ok, ed[0] == 1 && ml[0] == 1);
        let stripped = ReceiptSignature::Ed25519Only(ed);
        assert!(!verify_signature::<Floor>(&key, CryptoFloor::HybridEd25519MlDsa65, b"m", &stripped));
    }

    #[kani::proof]
    fn projection_never_allows_when_not_verified() {
        let verified: K3 = kani::any();
        let receipt_verdict: u8 = kani::any();
        kani::assume(receipt_verdict < 3);
        let allow_feasible = verified == K3::Pos && receipt_verdict == 0;
        let learned: i32 = kani::any();
        let tau: i32 = kani::any();
        let env = kani_only::envelope_from_parts(allow_feasible);
        let action = env.project(Some(FixedQ16_16(learned)), FixedQ16_16(tau));
        if verified != K3::Pos || receipt_verdict != 0 { assert_eq!(action, EdgeAction::Deny); }
        assert_eq!(env.project(None, FixedQ16_16(tau)), EdgeAction::Deny);
    }
}
```

The one helper under `kani_only` is a `#[cfg(kani)]` constructor inside the core crate that exposes the private field to the harness alone. Production builds have no such path, so the private-constructor guarantee is intact.

**Apalache TLA+.** The model abstracts signatures as a set of verified subject-to-issuer pairs and quantifies the learned choice over the feasible set, which is the Wave 1 transfer idiom. Three invariants are checked by `apalache-mc check --inv=Inv_FallbackAlwaysFeasible,Inv_NoAcceptWithoutAnchor,Inv_NoDowngrade`.

```tla
-------------------------- MODULE FederatedReceiptVerify --------------------------
EXTENDS Integers

CONSTANTS
    \* @type: Set(Int);
    RootIds,
    \* @type: Set({ issuer: Int, floor: Int, issuedAt: Int, expiresAt: Int, allow: Bool });
    Receipts,
    \* @type: Int -> Int;
    MinFloor

VARIABLES
    \* @type: Set(Int);
    trusted,
    \* @type: Set(<<Int, Int>>);
    cross,
    \* @type: Set({ issuer: Int, floor: Int, issuedAt: Int, expiresAt: Int, allow: Bool });
    accepted,
    \* @type: Int;
    now

Subjects(S) == { s \in RootIds : \E r \in S : <<s, r>> \in cross }
Reach1 == trusted \cup Subjects(trusted)
Reach2 == Reach1 \cup Subjects(Reach1)
Resolvable == Reach2 \cup Subjects(Reach2)   \* unrolled to MAX_CROSS_CERT_DEPTH

WindowCode(t, i, e) == IF t < i THEN 1 ELSE IF e <= t THEN 2 ELSE 0

Feasible(rc) ==
    {"deny"} \cup
    (IF /\ rc.issuer \in Resolvable
        /\ rc.floor >= MinFloor[rc.issuer]
        /\ WindowCode(now, rc.issuedAt, rc.expiresAt) = 0
        /\ rc.allow
     THEN {"allow"} ELSE {})

Init == trusted = {} /\ cross = {} /\ accepted = {} /\ now = 0

AddTrusted(r) == trusted' = trusted \cup {r} /\ UNCHANGED <<cross, accepted, now>>

AddCross(s, r) ==
    /\ r \in Resolvable /\ s \notin trusted
    /\ cross' = cross \cup {<<s, r>>}
    /\ UNCHANGED <<trusted, accepted, now>>

Tick == now' = now + 1 /\ UNCHANGED <<trusted, cross, accepted>>

Decide(rc) ==
    \E a \in Feasible(rc) :
        /\ accepted' = IF a = "allow" THEN accepted \cup {rc} ELSE accepted
        /\ UNCHANGED <<trusted, cross, now>>

Next ==
    \/ \E r \in RootIds : AddTrusted(r)
    \/ \E s, r \in RootIds : AddCross(s, r)
    \/ \E rc \in Receipts : Decide(rc)
    \/ Tick

Inv_FallbackAlwaysFeasible == \A rc \in Receipts : "deny" \in Feasible(rc)
Inv_NoAcceptWithoutAnchor == \A rc \in accepted : rc.issuer \in Resolvable
Inv_NoDowngrade == \A rc \in accepted : rc.floor >= MinFloor[rc.issuer]
===================================================================================
```

The first invariant is the envelope law. The second says that acceptance implies an anchored chain, and it is stable because the model only grows trust. The third is Theorem T2 at the policy level. The `Decide` action is where every trained model lives. Changing the model changes nothing in this module, which is why the proofs discharge once.

**What this adds to the repository.** One new `#![no_std]` crate for the lift, the receipt, and the verifier. Three thin adapter modules in the existing edge crates. One additive metadata constant and predicate in `chio-core-types`. One Lean module, one Kani file, and one TLA+ module, all new. No pinned signature in `formal_core.rs`, `formal_aeneas.rs`, `budget_split.rs`, or `pipeline.rs` changes, so no existing proof breaks.

Recap. The three protocol edges now lift into one canonical, injectively encoded `PortableToolCallRequest` with the four Copley roles, and only the verified core touches those bytes. Receipts carry a signed hybrid floor over Ed25519 and ML-DSA-65, verified as a conjunction, with hardware attestation bound through the signed evidence hash. Offline verification resolves federated roots through bounded cross-certificate chains and projects onto an envelope whose fallback is always `Deny`. The Lean, Kani, and Apalache artifacts are additive, pin the kernel mirrors by equivalence, and model the learned choice as nondeterminism so that retraining never reopens a proof. Next is wiring the backend implementations of the three crypto traits and the attestation verifier into the kernel's signer and running the Kani equivalence harnesses against the pinned kernel functions.