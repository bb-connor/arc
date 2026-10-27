# Kernel Decision Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Every task is RED first: the named tests are written and fail before the implementation lands. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the kernel a bounded, verifiable decision-model seam. A learned or heuristic component proposes; the kernel's algebraic envelope decides. Concretely: a float-free fixed-point crate, a sealed projection wrapper that makes every learned proposal land inside the feasible set or fall back to the conservative action, a `no_std` three-valued predicate DAG evaluator with a static work bound, a kernel guard that runs the DAG and seals a committed-safe witness into the signed receipt, and a cost-aware guard ordering that provably preserves the verdict and the deny attribution. The encoder that produces predicate scores never runs in the kernel; the kernel consumes attested scores and sealed thresholds only.

**Base:** `origin/main` at `6bc224b6a0` or later. Research inputs are the untracked integration map and wave synthesis set under `docs/`, which stay out of the public mirror. This plan is the only document the PR series cites.

**Naming:** public names are generic. No research-project or model-project names appear in crate names, types, docs, comments, schema ids, feature flags or fixture file names. The 537-atom / 236-rule table is "the reference model" and ships as a signed model artifact fixture, never as source constants.

**Not in scope (follow-on tracks, not planned here):** shadow-price micro-models and the dual-ascent controller in `chio-autonomy`, the swarm ready-frontier scheduler, the recovery planner heuristic, pheromone route scoring, cgroup sizing, the Tier-1 encoder sidecar, protocol-edge receipt formats, enclave attestation. Each needs the primitives this plan lands and gets its own plan.

## Global constraints

- Fail-closed: every decode, load and evaluate error denies. An invalid schedule, threshold table or model card is refused at load, never at first call.
- No legacy or compat: every caller changes in the same PR; no dual APIs, no default trait methods that preserve an old shape.
- `no_std` and alloc-free for `chio-fixed`, `chio-decision-model`, `chio-predicate-dag`. Crate-level `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing, clippy::as_conversions, clippy::float_arithmetic)]` (test modules may `allow` `arithmetic_side_effects` and `indexing_slicing`). Workspace lints already deny `unwrap_used` and `expect_used`.
- Checked arithmetic only. A silent clamp is an authority grant (the `overflow-checks` rationale in the root `Cargo.toml`). Overflow returns `None` or a typed error and the caller falls back.
- No em dashes anywhere. Conventional commits. `cargo fmt --all`, never standalone `rustfmt`.
- Every `#[kani::proof]` lives in the crate's `src/kani_public_harnesses.rs`, is registered in `.kani/harnesses.toml` (the only Kani registry) and has a `formal/MAPPING.md` row. `scripts/check-mapping.sh` gains the new harness files in its source list.
- Any test or fixture that reads time uses a fixed finite timestamp and passes `scripts/check-security-clocks.py`.
- Module size cap: 2000 lines production, 1000 lines `lib.rs` (`scripts/check-rust-file-hygiene.py`). Split before, not after.
- Every new signed or metadata schema id is `.v1`, registered in `spec/schemas/registry.json`, and passes `scripts/check-chio-schema-registry.sh` and `scripts/check-chio-owned-v1-only.sh`.

## Decisions (each open question the synthesis left, closed here)

| # | Question | Decision | Rationale |
|---|---|---|---|
| D1 | Fixed-point type | `Q16_16(i32)`, `#[repr(transparent)]`, private field, in `crates/core/chio-fixed`. No `Q32`, no `Q8.24`, no second copy anywhere. | 4-byte lanes bit-blast cheaply in Kani; 2^-16 matches the quantized margin resolution; one type ends the four-name drift. |
| D2 | Rounding | Floor (arithmetic shift) for `checked_mul` and `checked_div`. | Floor is the only convention every wave's Lean sketch proves against; Aeneas extracts it directly. |
| D3 | Overflow | `checked_*` returns `None`. No `saturating_*` in the public API. | Silent clamp is an authority grant; a `None` forces the envelope fallback. |
| D4 | `exp2` lookup table and shadow-price vector | Not in this plan. | No consumer in scope; adding unused surface violates the public-surface gate's intent. |
| D5 | Sealed wrapper | `Envelope<'a, A>` (feasible slice plus fallback) and `Projected<A>` (private field, `action()`, `outcome()`), with `ProjectionOutcome::{Identity, Clipped, Fallback(FallbackReason)}`. | The integration map's canonical pair; the outcome tag is what the witness and the Simplex telemetry need, and W9/W14's tagless version loses it. |
| D6 | Fallback | The conservative action is always `feasible[0]` and the constructor refuses a slice that does not contain it. The kernel's fallback for verdicts is `Verdict::Deny`. | Non-vacuity by construction (P1.1); Deny is the meet of the verdict lattice. |
| D7 | Where the DAG evaluator lives | New crate `crates/guards/chio-predicate-dag`, not a `chio-kernel-core` module. `chio-kernel-core` does not depend on it. | Keeps the portable kernel build small and under the file cap; the only kernel consumer is a guard, which lives in `chio-guards` anyway. |
| D8 | Rule normal form | A rule is an AND of at most 16 OR-clauses over literals; a literal is a possibly negated atom or a possibly negated earlier rule. | W9 and W14 (latest) converge here; it is the form the staged schedule evaluates branch-free. |
| D9 | Rule polarity | `Deny`, `Hold`, `Advisory`. No `Enable` or allow rules. | A learned rule may only narrow admission (monotone-narrowing theorem); widening rules would need a non-interference proof this plan does not fund. |
| D10 | Three-valued semantics | Strong Kleene. `s >= tau_pos` is True, `s < tau_neg` is False, otherwise Unknown; constructor enforces `tau_neg <= tau_pos`. Deny rule True gives `Deny`; no Deny True but any Deny or Hold rule Unknown or any Hold rule True gives `PendingApproval`; otherwise `Allow`. | Matches the pipeline's sticky `PendingApproval`; a missing or unattested score degrades to review, never to allow. |
| D11 | Capacity | Fixed caps, not const generics: 1024 atoms (16 words), 512 rules (8 words), 4096 clauses, 16 literals per clause, `MAX_SCHEDULE_OPS = 65_536`. `const _` asserts pin padding masks. | The reference model (537 / 236 / 2124 clauses) fits with margin; fixed caps keep Kani unwind bounds and the wire format static. |
| D12 | Work metering | Charge `schedule.op_count()` once against the shared `VerificationBudget` before evaluating; refuse at load when `op_count() > MAX_SCHEDULE_OPS`. No prefix or staged partial evaluation in v1. | WCET is a static property of a validated schedule; per-op charging buys nothing and prefix soundness adds proof surface without a consumer. |
| D13 | Work meter home | Move `VerificationBudget` from `chio-semantic-contracts::work` to `chio_security_types::work` with an explicit cap argument; `chio-semantic-contracts`, `chio-recovery` and `chio-store-sqlite` import it from there. | One struct, as the integration map requires; `chio-security-types` is `no_std`-capable with only `serde` and `serde_json` as dependencies, so the DAG crate can depend on it. |
| D14 | Schedule and threshold wire | One canonical binary artifact `chio.decision-model.v1`: header, atom count, rule count, threshold pairs (Q16.16 LE), op stream. The `no_std` crate decodes and validates from `&[u8]` into caller-owned storage; the std loader hashes the exact bytes. | Caller-owned storage keeps the evaluator alloc-free; one artifact means one digest to pin. |
| D15 | Model pinning | The artifact's SHA-256 is the `weights_hash` of a `chio-weights` `ModelCard`; the guard loads only through `evaluate_weights_binding`. No new snapshot store, no epoch store. | Reuses cosign, hashing, Kani-covered card validation; the integration map forbids a parallel weights path. |
| D16 | Score source | `ScoreSource` trait in `chio-guards`: `fn scores(&self, ctx) -> Result<ScoreFrame, ScoreError>`, where `ScoreFrame` holds `Q16_16` per atom plus an `attested: bool` per atom. One shipped impl, `ExactPredicateSource` (in-process deterministic predicates over the request, none learned). A model whose schedule references an atom no configured source provides is refused at load. Unattested scores are Unknown. | The encoder stays out of the kernel; absent evidence degrades to review, and the load-time check keeps "works but always pending" from shipping by accident. |
| D17 | Witness location | New reserved key `decision_model_witness` in `RECEIPT_METADATA_KEYS` (#1727), `ChioInternal`, `CommittedSafe`, schema `chio.decision-model-witness.v1`. Never a top-level `ChioReceiptBody` field, never nested under `model_metadata`. | `ChioReceiptBody` is frozen by M1 item 2; `model_metadata` is registered `Unsafe` (caller values), so nesting there would strip the witness from committed receipts. |
| D18 | Witness contents | Committed block carries only: schema, `model_card_digest`, `artifact_digest`, `outcome`, `rules_fired_hex` (8 words), `rules_unknown_hex`, `work_ops`, `projection_outcome`, `fallback_reason`. Atom bitmaps and per-atom margins are NOT in the signed block; they are written as a `MetadataCommitment` under `salt_ref = "metadata.decision_model.atoms"` once M1 item 2 F lands, and are not written anywhere before that. | A predicate bitmap is a classification of the arguments, which the registry's committed-safe audit treats as argument-derived; rule ids already appear in the deny reason text and are static per model. |
| D19 | How a guard contributes a typed block | `GuardDecision` gains `witness: Option<DecisionModelWitness>`. `GuardPipeline` carries at most one; two witnesses in one evaluation deny (fail closed). The kernel merges it under the reserved key beside the other kernel blocks. | Minimal seam; a guard never writes raw metadata, so the reserved-key invariant (signer-authored) holds. |
| D20 | Guard ordering seam | Registration-side: `GuardPipeline::add_reorderable(guard, cost: GuardCost)`. No new `Guard` trait method. Registration refuses a guard unless `evidence_declaration().details == Safe` and `!requires_dispatch_revalidation()`. | Ordering is pipeline policy, not a guard property; avoids a second 111-impl churn after #1727. |
| D21 | Ordering input | A static, operator-supplied `deny_prior_q16` per reorderable guard; ratio `deny_prior / cost_units` compared by `u64` cross-multiplication, ties by registration index. No online learning in v1. | The verdict-preservation proof is about the permutation, not about where the permutation came from; online priors come with the autonomy track. |
| D22 | Attribution under permutation | On a reordered Deny, run the completion scan over skipped reorderable guards with registration index below the denier's; the evidence vector is rebuilt in registration order so it is byte-identical to the fixed-order run. Allow-arm evidence is also rebuilt in registration order. | W2's stronger property (byte-identical evidence) is what makes receipts replayable; W4's "same verdict kind" is not enough for a signed receipt. |
| D23 | Formal placement | Kani harnesses per crate in `kani_public_harnesses.rs`. Lean under `formal/lean4/Chio/DecisionModel/`. One Apalache module `formal/apalache/DecisionEnvelope.tla` with one negative mutant. No wave-named crates or modules. | Follows the existing registries and gates; wave-named modules are research residue. |
| D24 | `no_std` CI target | `scripts/check-portable-kernel.sh` builds the three alloc-free crates for `wasm32-unknown-unknown` and `thumbv7em-none-eabi` with `--no-default-features`. | `thumbv7em` has no allocator, so it is the proof that the crates are alloc-free, not only `std`-free. |
| D25 | Loom and DST | Out of scope for this plan. Nothing here publishes shared mutable state; the model is immutable after load. | The epoch-swap concurrency work belongs with the weights-epoch track. |

## New crates

### `crates/core/chio-fixed`

- `#![no_std]`, no alloc. Deps: none (dev: `proptest`). Feature `kani` (empty, for manifest symmetry).
- Public API:

```rust
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Q16_16(i32);

impl Q16_16 {
    pub const FRAC_BITS: u32 = 16;
    pub const ZERO: Self; pub const ONE: Self; pub const MAX: Self; pub const MIN: Self;
    pub const fn from_bits(bits: i32) -> Self;
    pub const fn to_bits(self) -> i32;
    pub const fn from_int(v: i16) -> Self;            // always representable
    pub fn from_bps(bps: u16) -> Option<Self>;        // bps <= 10_000, floor
    pub fn checked_add(self, o: Self) -> Option<Self>;
    pub fn checked_sub(self, o: Self) -> Option<Self>;
    pub fn checked_mul(self, o: Self) -> Option<Self>; // floor((a*b) >> 16) via i64
    pub fn checked_div(self, o: Self) -> Option<Self>; // floor((a << 16) / b), None on b == 0
    pub fn checked_neg(self) -> Option<Self>;
    pub fn floor_to_int(self) -> i16;
}

/// Left-to-right checked sum; the order is part of the contract.
pub fn checked_sum(terms: &[Q16_16]) -> Option<Q16_16>;
/// Left-to-right checked dot product.
pub fn checked_dot(a: &[Q16_16], b: &[Q16_16]) -> Option<Q16_16>; // None on length mismatch
/// Cross-multiplied ratio order a/b vs c/d with b, d > 0 (no division).
pub fn ratio_cmp(a: u32, b: u32, c: u32, d: u32) -> Option<core::cmp::Ordering>;
```

- Serde: `impl Serialize/Deserialize` as the raw `i32` bits under feature `serde` (`default-features = false`).

### `crates/core/chio-decision-model`

- `#![no_std]`, no alloc. Deps: `chio-fixed`.
- Public API:

```rust
pub enum FallbackReason { EmptyProposal, ProposalInfeasible, ScorerError, WorkExhausted, PolicyUnavailable }
pub enum ProjectionOutcome { Identity, Clipped, Fallback(FallbackReason) }

/// A feasible set with its conservative element at index 0.
pub struct Envelope<'a, A: Copy + Eq> { feasible: &'a [A] }   // private
pub enum EnvelopeError { Empty, TooLarge }                      // len > MAX_ENVELOPE_ACTIONS (256)

impl<'a, A: Copy + Eq> Envelope<'a, A> {
    pub fn new(feasible: &'a [A]) -> Result<Self, EnvelopeError>;
    pub fn fallback(&self) -> A;                   // feasible[0]
    pub fn admits(&self, a: A) -> bool;
    /// Total: every proposal yields an admitted action.
    pub fn project(&self, proposal: Result<Option<A>, FallbackReason>) -> Projected<A>;
    /// Argmax over scores with first-maximum tie break; length mismatch is Fallback.
    pub fn select(&self, scores: &[chio_fixed::Q16_16]) -> Projected<A>;
}

pub struct Projected<A> { action: A, outcome: ProjectionOutcome } // private fields
impl<A: Copy> Projected<A> {
    pub fn action(&self) -> A;
    pub fn outcome(&self) -> ProjectionOutcome;
    pub fn fallback_used(&self) -> bool;
}
```

- `compile_fail` doctests: `Projected<A>` has no public constructor and no `From<A>`; `Envelope::new` is the only entry.

### `crates/guards/chio-predicate-dag`

- `#![no_std]`, no alloc. Deps: `chio-fixed`, `chio-security-types` (`default-features = false`, for `VerificationBudget`). Feature `serde` off by default.
- Constants: `MAX_ATOMS = 1024`, `ATOM_WORDS = 16`, `MAX_RULES = 512`, `RULE_WORDS = 8`, `MAX_CLAUSES = 4096`, `MAX_LITERALS_PER_CLAUSE = 16`, `MAX_SCHEDULE_OPS = 65_536`, `ARTIFACT_MAGIC = b"CDM1"`.
- Public API:

```rust
#[derive(Clone, Copy, PartialEq, Eq)] pub enum Trit { True, False, Unknown }

/// Paired bit planes; invariant pos & neg == 0, padding bits zero.
pub struct TriSet<const W: usize> { pos: [u64; W], neg: [u64; W] }  // private
impl<const W: usize> TriSet<W> {
    pub fn new(pos: [u64; W], neg: [u64; W], live_bits: usize) -> Result<Self, DagError>;
    pub fn get(&self, i: usize) -> Option<Trit>;
    pub fn pos_words(&self) -> &[u64; W]; pub fn neg_words(&self) -> &[u64; W];
}

pub struct Thresholds { pairs: [(Q16_16, Q16_16); MAX_ATOMS], len: usize } // neg <= pos enforced
pub struct ScoreFrame<'a> { pub scores: &'a [Q16_16], pub attested: &'a [u64; ATOM_WORDS] }
/// Branch-free classification; an unattested atom is Unknown.
pub fn classify(scores: &ScoreFrame<'_>, tau: &Thresholds) -> Result<TriSet<ATOM_WORDS>, DagError>;

#[derive(Clone, Copy, PartialEq, Eq)] pub enum RulePolarity { Deny, Hold, Advisory }

/// Validated, acyclic, canonical op stream in caller-owned storage.
pub struct Schedule<'s> { /* ops: &'s [Op], rule_polarity, counts ... */ }
pub struct ScheduleStorage { ops: [Op; MAX_SCHEDULE_OPS], ... }   // caller owns, e.g. Box in std
pub enum DagError { BadMagic, BadLength, AtomOutOfRange, RuleOutOfRange, Cycle, TooManyOps,
                    TooManyClauses, ClauseNotCanonical, DuplicateClause, PaddingNotZero,
                    ThresholdOrder, PlaneOverlap, UnprovidedAtom, WorkExhausted }

impl<'s> Schedule<'s> {
    /// Decode and validate `chio.decision-model.v1` bytes into `storage`. Fail closed.
    pub fn decode(bytes: &[u8], storage: &'s mut ScheduleStorage) -> Result<(Self, Thresholds), DagError>;
    pub fn op_count(&self) -> u32;                 // the WCET in ops
    pub fn atom_count(&self) -> usize; pub fn rule_count(&self) -> usize;
    pub fn referenced_atoms(&self) -> &[u64; ATOM_WORDS];
    /// Charges op_count() once against `budget`; branch-free bit-plane evaluation.
    pub fn evaluate(&self, atoms: &TriSet<ATOM_WORDS>, budget: &mut VerificationBudget)
        -> Result<Evaluation, DagError>;
}

pub struct Evaluation { pub rules: TriSet<RULE_WORDS>, pub outcome: Outcome, pub work_ops: u32 }
#[derive(Clone, Copy, PartialEq, Eq)] pub enum Outcome { Allow, Hold, Deny }
```

- Op set (8 opcodes, W14): `Nop`, `AccAtomPos{word, mask}`, `AccAtomNeg{word, mask}`, `AccRulePos{word, bit}`, `AccRuleNeg{word, bit}`, `EndClause`, `Join`, `EndRule{rule, polarity}`. `fill(b) = 0u64.wrapping_sub(b)` is the one allowed wrapping op and is isolated in `fn fill` with a test pinning both values.
- Canonical form the decoder enforces: literals in a clause sorted by `(kind, id, negated)` with no duplicate literals; clauses within a rule sorted; no duplicate clause within a rule; complementary literals in one clause are kept (dropping them is unsound in Kleene logic); rule ids strictly increasing in the op stream; every referenced rule id smaller than the current rule id (acyclic by construction).

## Kernel integration seam

Files on `main` the seam touches (all after #1727, #1736 and #1710 land):

| File | Change |
|---|---|
| `crates/kernel/chio-kernel/src/kernel/mod.rs` | `GuardDecision { verdict, evidence, witness: Option<DecisionModelWitness> }`; `allow()`, `allow_with_evidence()`, `deny()` set `witness: None`; new `with_witness(self, w)`. |
| `crates/kernel/chio-kernel/src/kernel/dispatch.rs` (near line 1404, where guard evidence is appended) | Collect the single witness alongside evidence; two witnesses deny with `KernelError::GuardFailed { reason: "duplicate decision-model witness" }`. |
| `crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs` | Merge `decision_model_witness` as a kernel block through `merge_metadata_objects`, after caller metadata, with the same collision refusal as the other reserved keys. |
| `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs` | Carry the witness through `pre_invocation_guard_evidence`'s neighbour so a Deny-at-dispatch receipt still binds it. |
| `crates/guards/chio-guards/src/pipeline.rs` | Propagate `witness` (at most one) and the reorderable schedule (Phase 7). |
| `crates/guards/chio-guards/src/lib.rs` | `pub mod predicate_dag; pub use predicate_dag::{PredicateDagGuard, ScoreSource, ExactPredicateSource, DecisionModelLoadError};` |
| `crates/kernel/chio-kernel-core/src/guard.rs` | No change. The portable `Guard` returns `Verdict`, so the portable pipeline cannot carry a witness; the DAG guard is a full-kernel guard. |

The guard:

```rust
pub struct PredicateDagGuard { card: VerifiedModelCard, artifact_digest: [u8; 32],
                               storage: Box<ScheduleStorage>, schedule: Schedule<'static>,
                               thresholds: Thresholds, source: Box<dyn ScoreSource>,
                               work_cap: u32 }
impl PredicateDagGuard {
    /// Verifies the card bundle, checks `weights_hash == sha256(artifact)`, decodes and
    /// validates the artifact, and refuses any atom the source does not provide.
    pub fn load(card: VerifiedModelCard, artifact: &[u8], source: Box<dyn ScoreSource>, work_cap: u32)
        -> Result<Self, DecisionModelLoadError>;
}
impl chio_kernel::Guard for PredicateDagGuard {
    fn name(&self) -> &str { "predicate-dag" }
    fn evidence_declaration(&self) -> GuardEvidenceDeclaration { GuardEvidenceDeclaration::SAFE }
    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError>;
    // Deny -> evidence "action=deny; reason=rule:<id>" per fired Deny rule; Hold -> PendingApproval.
}
```

Model binding goes through `chio_kernel::weights_binding::evaluate_weights_binding` with the DAG's requested scopes equal to the pipeline's tool scope set, so a card's `banned_tools` and `allowed_capability_set` apply to the decision model exactly as to a provider.

## Receipt and witness wire additions

| Touchpoint | Addition |
|---|---|
| `crates/core/chio-core-types/src/receipt/metadata/key_registry.rs` (from #1727) | `spec("decision_model_witness", ChioInternal, CommittedSafe, Some(DECISION_MODEL_WITNESS_SCHEMA), "Decision-model witness: model card and artifact digests, static rule ids fired or unknown, outcome, work count and projection outcome. No argument, result, atom bitmap or margin. Read by the kernel's replay path and the offline verifier.")`. |
| `crates/core/chio-core-types/src/receipt/metadata/decision_model.rs` (new) | `DECISION_MODEL_WITNESS_METADATA_KEY`, `DECISION_MODEL_WITNESS_SCHEMA = "chio.decision-model-witness.v1"`, `DecisionModelWitness` with `#[serde(rename_all = "snake_case", deny_unknown_fields)]`, closed enums through `chio_security_types::lossless_serde!`, and `validate()` (schema pinned, both digests lowercase 64-hex, bitmap hex exactly 128 chars, `outcome == Deny` implies `rules_fired_hex != 0`). |
| `crates/core/chio-core-types/src/receipt/metadata.rs` | `pub mod decision_model;` and re-exports. |
| `spec/PROTOCOL.md` 6.4 | One registry row (rendered from the registry, same wording as `reason`) and a 6.4.x subsection `chio.decision-model-witness.v1` with the field table and the replay rule: a verifier with the artifact and the opened atom commitment recomputes `rules_fired_hex`, `rules_unknown_hex` and `outcome`; a verifier without the opening checks digests, shape and the deny-implies-fired rule only. |
| `spec/schemas/chio-wire/v1/receipt/decision-model-witness.schema.json` (new) and `spec/schemas/registry.json` | Draft 2020-12 schema, `additionalProperties: false`; registry entry `introducedBy: decision-model-witness-v1`. Run `cargo xtask codegen --check` for all four languages and commit the generated outputs. |
| `spec/schemas/chio-wire/v1/decision-model/artifact.schema.json` (new) | Documents the binary artifact header only (magic, version, counts, digest). The binary layout is normative in PROTOCOL 6.4.x. |
| M1 item 2 F (not this plan) | `salt_ref = "metadata.decision_model.atoms"` opening carrying `atoms_pos_hex`, `atoms_neg_hex`, `min_margin_q16`. This plan reserves the `salt_ref` string in the PROTOCOL text and writes no atom data until F lands. |

Witness fields: `schema`, `model_card_digest`, `artifact_digest`, `outcome` (`allow` / `hold` / `deny`), `rules_fired_hex`, `rules_unknown_hex`, `work_ops` (u32), `projection_outcome` (`identity` / `clipped` / `fallback`), `fallback_reason` (optional, present iff `fallback`).

## Phases

Each phase is one PR. Order is a dependency order; phases marked parallel may land in any order among themselves. "Gate" lists what must be green at the exact head before READY, in addition to the standard one-liner `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`.

### Phase 1: `feat(fixed): Q16.16 checked fixed point` (no dependencies)

Files: `crates/core/chio-fixed/{Cargo.toml, src/lib.rs, src/q16.rs, src/ratio.rs, src/kani_public_harnesses.rs, tests/properties.rs}`, root `Cargo.toml` members, `.kani/harnesses.toml`, `formal/MAPPING.md`, `scripts/check-mapping.sh`, `scripts/check-portable-kernel.sh` (add the crate for wasm32 and thumbv7em), `AGENTS.md` crate map row.

- [ ] RED: `tests/properties.rs` proptest: `checked_mul` equals `floor(a*b / 2^16)` computed in `i128`, or `None` exactly when out of `i32`; `checked_sum` is `None` iff some prefix overflows; `ratio_cmp` agrees with `u128` exact comparison; `from_bps(10_001)` is `None`.
- [ ] RED: Kani `verify_q16_checked_mul_matches_i128_reference`, `verify_q16_checked_add_never_wraps`, `verify_ratio_cmp_total_order` (unwind 1, `pr` lane).
- [ ] Implement; add `const _` asserts for `ONE`, `MAX`, `MIN` bit patterns.
- [ ] Gate: `scripts/check-portable-kernel.sh` (both targets), `scripts/check-kani-smoke.sh`, `scripts/check-mapping.sh`, `cargo xtask check crate-paths`.

### Phase 2: `refactor(security-types): one VerificationBudget` (parallel with Phase 1)

Files: `crates/security/chio-security-types/src/work.rs` (new), `src/lib.rs`; `crates/security/chio-semantic-contracts/src/work.rs` (keep `units()` only), `src/{lib.rs, constraints.rs, graph.rs, plans.rs, registry.rs, selectors.rs, verification.rs}`, `tests/**` and `README.md`; `crates/security/chio-recovery/src/planning/search.rs`; `crates/platform/chio-store-sqlite/src/admission_operation_store/semantic_deployment/installation.rs` and its recovery_deployment test.

- [ ] RED: `chio-security-types` unit tests: `new(0, cap)` and `new(cap + 1, cap)` reject; exhausted refuses a zero charge; `charge` past remaining sets exhausted and errors.
- [ ] Move the struct with `pub fn new(units: u32, cap: u32) -> Result<Self, WorkBudgetError>`; `WorkBudgetError::{ZeroOrOverCap, Exhausted}`; `From<WorkBudgetError> for ContractError` in semantic-contracts. Every caller passes `MAX_RECOVERY_VERIFICATION_WORK` explicitly. Delete the old definition.
- [ ] Gate: `cargo test -p chio-semantic-contracts -p chio-recovery -p chio-store-sqlite`, `scripts/check-negative-assertions.py` (no baseline growth), `scripts/check-trust-boundaries.py`.

### Phase 3: `feat(decision-model): sealed envelope projection` (after Phase 1)

Files: `crates/core/chio-decision-model/{Cargo.toml, src/lib.rs, src/envelope.rs, src/outcome.rs, src/kani_public_harnesses.rs, tests/envelope.rs}`, root `Cargo.toml`, `.kani/harnesses.toml`, `formal/MAPPING.md`, `scripts/check-mapping.sh`, `scripts/check-portable-kernel.sh`, `AGENTS.md`.

- [ ] RED: tests: `project(Ok(Some(a)))` with `a` admitted is `Identity` and returns `a`; with `a` not admitted is `Fallback(ProposalInfeasible)` and returns `feasible[0]`; `project(Ok(None))` is `Fallback(EmptyProposal)`; `project(Err(r))` is `Fallback(r)`; `select` with a mismatched length is `Fallback(ScorerError)`; `select` ties pick the first maximum; `new(&[])` is `Err(Empty)`; `compile_fail` doctests for constructing `Projected` or converting an `A` into it.
- [ ] RED: Kani `verify_projection_total_and_admitted` (any proposal over `[u8; 4]` feasible set), `verify_projection_idempotent_on_admitted`, `verify_select_in_envelope`.
- [ ] Implement.
- [ ] Gate: portable script, Kani smoke, mapping.

### Phase 4: `feat(predicate-dag): no_std three-valued rule evaluator` (after Phases 1 and 2)

Files: `crates/guards/chio-predicate-dag/{Cargo.toml, src/lib.rs, src/trit.rs, src/thresholds.rs, src/artifact.rs, src/schedule.rs, src/eval.rs, src/kani_public_harnesses.rs, tests/reference.rs, tests/artifact_rejections.rs, tests/fixtures/}`, root `Cargo.toml`, `.kani/harnesses.toml`, `formal/MAPPING.md`, `scripts/check-mapping.sh`, `scripts/check-portable-kernel.sh`, `AGENTS.md`.

- [ ] RED: `tests/reference.rs`: a 200-line reference interpreter (naive recursive Kleene over clauses and rules, `std`, test-only) and a proptest generator for random canonical DAGs up to 64 atoms / 32 rules; `Schedule::evaluate` equals the reference on every generated case and every input `TriSet`; tightening any threshold pair (raise pos or lower neg) never moves `outcome` toward `Allow` (monotone narrowing); `work_ops == op_count()`.
- [ ] RED: `tests/artifact_rejections.rs`: one mutated artifact per `DagError` variant is refused at `decode`; a valid artifact round-trips; `op_count() > MAX_SCHEDULE_OPS` refuses; `evaluate` with a budget smaller than `op_count()` is `WorkExhausted` and charges nothing.
- [ ] RED: fixture `tests/fixtures/reference-model.cdm` (the 537 / 236 reference model exported by the compiler below, with `reference-model.sha256`) and `tests/fixtures/reference-cells.bin` (the composer parity cells); test asserts zero mismatches against the reference interpreter. Fixture names are generic.
- [ ] RED: Kani `verify_classify_respects_thresholds`, `verify_eval_matches_reference_small` (4 atoms, 2 rules, unwind 10), `verify_tighten_never_widens_single_rule`, `verify_fill_is_zero_or_all_ones`.
- [ ] Implement `trit.rs`, `thresholds.rs`, `artifact.rs` (decoder and validator), `schedule.rs`, `eval.rs`. Keep each under 1000 lines.
- [ ] Add `xtask/src/decision_model_compile.rs`: `cargo xtask gen decision-model --rules <json> --thresholds <json> --out <cdm>` (std, offline, deterministic, emits canonical form; used to build the fixture; refuses non-canonical input instead of repairing it beyond sort and dedup).
- [ ] Gate: portable script, Kani smoke, mapping, `scripts/check-rust-file-hygiene.py`, `scripts/check-fuzz-budget.sh` after adding `fuzz/fuzz_targets/decision_model_artifact.rs` (decode never panics).

### Phase 5: `feat(core-types): decision-model witness metadata key` (after #1727 merges; parallel with Phase 4)

Files: `crates/core/chio-core-types/src/receipt/metadata/key_registry.rs`, `src/receipt/metadata/decision_model.rs` (new), `src/receipt/metadata.rs`, `tests/receipt_metadata_registry.rs` (from #1727), `tests/decision_model_witness.rs` (new), `spec/PROTOCOL.md` 6.4, `spec/schemas/chio-wire/v1/receipt/decision-model-witness.schema.json`, `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, generated SDK outputs (`cargo xtask codegen` for rust, ts, go, python), `docs/security/trust-boundary-inventory.json` (new raw decoder entry if the witness is decoded from untrusted bytes anywhere; otherwise none).

- [ ] RED: registry test asserts the key is present once, `ChioInternal`, `CommittedSafe`, schema pinned, and appears in the PROTOCOL table (the #1727 registry-to-table test).
- [ ] RED: witness tests: unknown field rejects; `deny` with zero `rules_fired_hex` rejects at `validate`; bad hex length rejects; marker property test: a witness built from any `Evaluation` never contains a 16-byte marker planted in request arguments (the M1 item 2 marker shape).
- [ ] Implement; run `cargo xtask codegen --check` for each language and commit.
- [ ] Gate: `scripts/check-chio-schema-registry.sh`, `scripts/check-wire-schemas.py`, `scripts/check-chio-owned-v1-only.sh`, `scripts/check-committed-receipt-raw-decode.py`, `scripts/check-sdk-parity.sh`.

### Phase 6: `feat(guards): predicate DAG guard with sealed receipt witness` (after Phases 3, 4, 5 and after #1727, #1736, #1710 merge)

Files: `crates/guards/chio-guards/src/predicate_dag.rs` (new), `src/predicate_dag/{exact_source.rs, load.rs}`, `src/lib.rs`, `src/pipeline.rs` (witness propagation only), `Cargo.toml` (`chio-predicate-dag`, `chio-decision-model`, `chio-fixed`, `chio-weights`), `tests/predicate_dag_guard.rs`; `crates/kernel/chio-kernel/src/kernel/mod.rs`, `src/kernel/dispatch.rs`, `src/kernel/kernel_drop_guard.rs`, `src/receipt_support/receipt_metadata.rs`, `src/kernel/tests/decision_model_witness.rs` (new), `src/lib.rs` (re-export `DecisionModelWitness`); `crates/kernel/chio-kernel/benches/fixtures/dispatch_request_fixture.rs` (GuardDecision shape); `docs/guards/01-CURRENT-GUARD-SYSTEM.md`; `docs/reference/KERNEL_EMBEDDING_GUIDE.md`.

- [ ] RED: kernel tests: an allow receipt from a pipeline containing the guard carries `metadata.decision_model_witness` that validates and whose digests match the loaded card and artifact; a deny receipt carries `outcome: deny` and the fired rule id in `evidence`; two guards both returning a witness deny the call with no receipt side effect; caller metadata naming `decision_model_witness` is refused before any effect (extends the existing reserved-key test).
- [ ] RED: guard tests: `load` refuses a card whose `weights_hash` differs from the artifact digest; refuses an artifact referencing an atom the source does not provide; an unattested atom yields `PendingApproval` when a Deny rule depends on it; Hold rule True yields `PendingApproval`; verdict projection through `Envelope<Verdict>` with feasible `[Deny, PendingApproval, Allow]` and the witness's `projection_outcome` records it; work cap below `op_count()` refuses at `load`, not at evaluate.
- [ ] RED: `chio-chaos` fault (`bench/chio-chaos/tests/kernel_faults.rs`): a `ScoreSource` that errors yields Deny with `fallback_reason: scorer_error` in the witness.
- [ ] Implement `GuardDecision.witness`, dispatch collection, metadata merge, the guard and `ExactPredicateSource` (tool name, server id, argument key presence and JSON type predicates; no value copying).
- [ ] Gate: `cargo test -p chio-kernel -p chio-guards`, `scripts/check-trust-boundaries.py`, `scripts/check-security-clocks.py`, `scripts/check-negative-assertions.py`, `scripts/check-adapter-no-bypass.sh`, `scripts/check-receipt-trace.sh`, `cargo xtask check formal-mirrors` (the kernel symbols touched are not in any mirror today; confirm), regenerate `docs/formal/COVERAGE.md` as the last commit.

### Phase 7: `feat(guards): cost-ordered pure guards with canonical attribution` (after #1727 and Phase 6)

Files: `crates/guards/chio-guards/src/pipeline.rs`, `src/pipeline/schedule.rs` (new), `tests/pipeline_schedule.rs` (new), `crates/kernel/chio-kernel/src/kernel/tests/guard_pipeline.rs`, `docs/guards/01-CURRENT-GUARD-SYSTEM.md`, `crates/guards/chio-guards/benches/pipeline_order.rs` (new, criterion).

- [ ] RED: differential proptest: for random guard sets (pure allow/deny/error guards with random `deny_prior_q16` and `cost_units`), the scheduled pipeline returns a `GuardDecision` byte-identical (verdict, evidence order and text, witness) to the registration-order pipeline; `add_reorderable` refuses a guard with `details: Unsafe` or `requires_dispatch_revalidation() == true`; a `PendingApproval` from a reorderable guard stays sticky; stateful guards never run before a reorderable Deny is settled.
- [ ] RED: Kani (in `chio-fixed`, since the comparator lives there): `verify_ratio_cmp_permutation_is_total` already covered; add in `chio-guards` a unit test over the 4-guard exhaustive permutation space.
- [ ] Implement `GuardSchedule { order: Vec<usize>, completion_scan: bool }` computed at registration from `ratio_cmp(deny_prior, cost, ...)` with index tie break; evaluate runs reorderable prefix in schedule order, completion scan on Deny, then stateful guards in registration order; rebuild evidence by registration index.
- [ ] Bench gate recorded in the PR body: p99.9 scheduled <= p99.9 registration-order + 600 ns on the 16-guard fixture.
- [ ] Gate: `cargo test -p chio-guards -p chio-kernel`, `scripts/check-regression-tests.sh`.

### Phase 8: `docs(formal): Lean and Apalache models for the decision envelope` (after Phases 3 and 4; parallel with 6 and 7)

Files: `formal/lean4/Chio/DecisionModel/{Fixed.lean, Envelope.lean, Kleene.lean}`, `formal/lean4/lakefile` entries, `formal/apalache/DecisionEnvelope.tla`, `formal/apalache/negative/DecisionEnvelopeNoFallback.tla`, `formal/proof-manifest.toml` (`[[mirror]]` rows for `Envelope::project`, `Schedule::evaluate`, `classify`; new `[[proof]]` rows), `formal/MAPPING.md`, `scripts/check-apalache-positive.sh` and `check-apalache-negative.sh` lists, `docs/formal/COVERAGE.md` (regenerated last).

- [ ] Lean: `checked_mul_spec` (floor semantics against `Int`), `project_mem` (projection admitted), `project_idem`, `kleene_and_or_monotone_info`, `tighten_no_widen` (raising `tau_pos` or lowering `tau_neg` on Deny and Hold rules never moves the outcome toward Allow). Core Lean only, no Mathlib.
- [ ] Apalache: invariants `ChosenInFeasible`, `WitnessBeforeAllow`; the negative mutant drops the fallback and must produce a trace.
- [ ] Gate: `scripts/check-formal-proofs.sh`, `scripts/check-apalache-positive.sh`, `scripts/check-apalache-negative.sh`, `cargo xtask check formal-mirrors`, `cargo xtask gen proof-coverage --check`.

### Phase 9: `ci(decision-model): gates and release wiring` (last)

Files: `.github/workflows/ci.yml` (portable-kernel job already runs the script; add the `thumbv7em-none-eabi` rustup target), `releases.toml` (pin the new job names only if a new job is added), `ci-gates/` facet if the artifact fixture is covered by `cargo xtask check fixtures`, `scripts/check-decision-model-float-free.sh` (new: `cargo tree -e normal -p chio-fixed -p chio-decision-model -p chio-predicate-dag` has no `libm`, `num-traits` float features or `f32`/`f64` tokens in the three crates), `scripts/check-release-source-gates.py` registration, `docs/operations/UNIFIED_ROADMAP.md` one row, `README.md` untouched.

- [ ] Gate: full one-liner, `scripts/check-release-source-gates.py`, `scripts/check-rust-verification-gates.sh`, `scripts/check-actions-workflow-syntax.py`.

## Collision map with in-flight PRs

| In-flight | Files shared with this plan | Rule |
|---|---|---|
| #1727 guard evidence declarations and key registry | `receipt/metadata.rs`, `metadata/key_registry.rs`, `tests/receipt_metadata_registry.rs`, `chio-guards/src/pipeline.rs`, `chio-kernel/src/kernel/mod.rs`, `chio-kernel-core/src/guard.rs`, `spec/PROTOCOL.md` 6.4, `docs/guards/01-CURRENT-GUARD-SYSTEM.md`, `bench/chio-chaos/tests/kernel_faults.rs`, `benches/fixtures/dispatch_request_fixture.rs` | Phases 5, 6, 7 start after #1727 merges. The `PredicateDagGuard` implements `evidence_declaration()` from day one. |
| #1736 evidence bundle verify | `chio-kernel/src/receipt_support/receipt_metadata.rs`, `chio-kernel/src/kernel/mod.rs`, `chio-kernel/src/lib.rs`, `chio-kernel-core/src/lib.rs`, `receipt/mod.rs`, `Cargo.toml`, `ci.yml` | Phase 6 after #1736. Phases 1 to 4 add `Cargo.toml` members only; rebase is mechanical. |
| #1710 settlement ledger hook, #1705 | `chio-kernel/src/kernel/mod.rs`, `src/lib.rs`, `docs/reference/KERNEL_EMBEDDING_GUIDE.md` | Phase 6 after #1710. |
| #1709 / #1759 / #1778 / #1783 root exchange | `chio-mcp-remote`, `root_authority/*`, `_generated/chio_wire_v1.rs`, SDK generated dirs | Phase 5 regenerates codegen outputs, so it lands after #1759 (which also regenerates them) to avoid a generated-file conflict. No source overlap otherwise. |

Phases 1, 2, 3, 4 touch no in-flight file and can start now.

## Release gates (what READY means for the track as a whole)

1. Portable proof: `scripts/check-portable-kernel.sh` green with the three new crates on `wasm32-unknown-unknown` and `thumbv7em-none-eabi`, `--no-default-features`.
2. Float-free: `scripts/check-decision-model-float-free.sh` green.
3. Kani `pr` lane green for every harness this plan registers; `scripts/check-kani-public-harnesses.py` and `scripts/check-mapping.sh` green.
4. Reference-model parity: zero mismatches between `Schedule::evaluate` and the reference interpreter over the committed parity cells, and `op_count()` of the reference artifact recorded in the PR body (expected well under `MAX_SCHEDULE_OPS`).
5. Receipt privacy: the marker property test and `scripts/check-committed-receipt-raw-decode.py` green; `decision_model_witness` registered `CommittedSafe` with a `reason` that names its field audit.
6. Verdict preservation: the Phase 7 differential proptest green with 10,000 cases and the exhaustive 4-guard permutation test.
7. Formal: `cargo xtask check formal-mirrors` and `gen proof-coverage --check` green; the Apalache negative mutant produces a trace.
8. Standard merge gate (integrate-fast): review ACK, light checks at the exact head, workspace check after rebase, Codex P1/P2 threads cleared. Native and Loom runs post-merge.

## Risks

| Risk | Mitigation |
|---|---|
| The reference model's compiled schedule exceeds `MAX_SCHEDULE_OPS` after canonicalization. | Phase 4 measures the real artifact first; the cap is a `const` in one place and the WCET gate records the number. W9 to W14 estimate 19k to 24k ops. |
| A decision-model witness in every receipt changes receipt ids for every fixture in the repo. | The key is written only when a `PredicateDagGuard` is in the pipeline; default pipelines do not include it, so existing signed fixtures are untouched. |
| "Always PendingApproval" in deployments without a score source. | D16 refuses to load an artifact that references atoms no source provides; `ExactPredicateSource` covers deterministic atoms only, so a learned-atom model needs an explicit source. |
| Rebase churn against #1727's 111 guard impls. | Phases 5 to 7 start only after #1727 merges; no second trait method is added (D20). |
| Kleene semantics diverge from the sidecar's boolean composer on Unknown atoms. | Parity cells are evaluated with every atom attested (Boolean mode is Kleene mode with no Unknown); the Kleene-only behaviour is covered by the reference interpreter and `tighten_no_widen`. |
| Guard reordering silently changes evidence text. | D22 rebuilds evidence in registration order and the differential test is byte-identical, not verdict-only. |
| Atom bitmaps leak argument properties before M1 item 2 F lands. | D18: no atom data is written anywhere until the commitment path exists. |
| Codegen regeneration conflicts with the root-exchange chain. | Phase 5 lands after #1759. |
| `chio-guards` is std and pulls tokio; a future wasm or mobile consumer wants the DAG guard. | The evaluator is `no_std`; a portable `Guard` wrapper for `chio-kernel-core` is a one-file follow-on once the portable `GuardDecision` grows a witness slot. |
