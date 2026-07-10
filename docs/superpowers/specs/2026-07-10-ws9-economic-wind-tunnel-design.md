# WS9 Design: Economic wind tunnel (adversarial economy arena)

- Date: 2026-07-10
- Program: agent-economy program, wave 3 (harness skeleton may land during wave 2; see `2026-07-10-agent-economy-program-design.md`)
- Depends on: attacks target wave-2 markets; WS8 parameters widen the attack surface
- Claim track: external evidence (produces signed economic-robustness matrices; makes no new capability claims itself)
- Branch: `chio/ws9-economic-wind-tunnel` off `main`

## Goal

The arena red-teams identity and capability security. It has no economic
adversaries. WS9 builds a deterministic economic wind tunnel: a suite of
seeded adversarial economic campaigns replayed against the real pure
economy validators, emitting signed pass/finding matrices. Each scenario
declares the fail-closed behavior an invariant should exhibit; a run that
observes a breach produces a finding routed like a bug, not a capability
claim. The matrices are the external-evidence artifact future underwriting
and insurance claims cite (`2026-07-10-agent-economy-program-design.md:150`).

## Context

The existing arena is security-only. `AdversaryClass`
(`crates/core/chio-arena/src/adversary/mod.rs:53`) enumerates exactly four
classes (prompt-injection, capability-overrequest, replay-attempt,
scope-escape), and the `Adversary` trait
(`crates/core/chio-arena/src/adversary/mod.rs:114`) is a per-step, pure
transformation of one `ScenarioStep` into one expected `ScenarioVerdict`
(allow/deny/rewrite), refereed by the kernel-and-guard pool. The curated
`chio-adversarial-suite` corpus is likewise security-only: `ATTACK_CLASSES`
(`crates/core/chio-adversarial-suite/src/lib.rs:24`) covers clock-rewound,
replayed-nonce, scope-superset, and similar identity attacks. No class
touches pricing, credit, oracles, fees, or settlement liveness.

What the arena does provide, and WS9 reuses, is a determinism substrate: a
seeded ChaCha20 PRNG and a fixed virtual clock (the determinism contract at
`crates/core/chio-arena/src/adversary/mod.rs:21` forbids wall-clock, thread
local, and network reads; two runs are byte-identical), a canonical-JSON
replay-bundle writer (`crates/core/chio-arena/src/promote.rs:149`, schema
`chio.arena.bundle/v1`, `sha256_hex` over canonical bytes), and a
determinism gate (`crates/core/chio-arena/tests/determinism_gate.rs`).

The economic invariants WS9 attacks already exist as pure validators (each
is one scenario class; Adversary suite tabulates targets and findings):

- Sybil tier gate. `qualifies_for_tier_3`
  (`crates/trust/chio-reputation/src/tier.rs:135`) requires composed score
  >= 0.90 AND every feed >= 0.80 AND >= 2 distinct feeds; a single-feed
  flood stays at tier_2 (`tier.rs:96`). Marketplace credit limits derive
  from `compute_marketplace_credit_limit`
  (`crates/economy/chio-underwriting/src/marketplace_limits.rs:82`).
- Open-market bidding. `bid` / `accept`
  (`crates/economy/chio-open-market/src/bidding.rs:308`, `bidding.rs:439`)
  fail closed on authority mismatch (`bidding.rs:341`), sub-ceiling bids
  (`bidding.rs:369`), out-of-scope requests (`bidding.rs:376`), and
  reservations that do not cover total liability (`bidding.rs:480`,
  `token_offer_total_liability` at `bidding.rs:512`).
- Credit exposure and underwriting. Exposure-ledger limits are bounded
  (`crates/economy/chio-credit/src/lib.rs:83`); the backtest surfaces
  over-utilization (`crates/economy/chio-credit/src/risk_reports.rs:401`,
  `risk_reports.rs:442`); the underwriting fuzz target guards monotonic
  tier ceilings and fail-closed revocation
  (`fuzz/fuzz_targets/underwriting_policy_input.rs:16`).
- Oracle circuit breaker. `ensure_within_threshold`
  (`crates/economy/chio-link/src/circuit_breaker.rs:49`) trips
  `CircuitBreakerTripped` when integer `divergence_bps`
  (`circuit_breaker.rs:19`) exceeds the threshold; `ExchangeRate` carries
  `max_age_seconds` for staleness.
- Fee thresholds. `Constraint::RequireApprovalAbove { threshold_units }`
  (`crates/core/chio-core-types/src/capability/scope.rs:300`) gates a
  single request at or above the threshold.
- Settlement liveness. `classify_attempt`
  (`crates/economy/chio-settle/src/retry.rs:123`) bounds retries at
  `DEFAULT_MAX_RETRIES` (`retry.rs:30`), short-circuits permanent outcomes
  (`retry.rs:135`), and converges to `DeadLetter` on exhaustion
  (`retry.rs:139`).

The output artifact follows the autonomy qualification matrix:
`AutonomousQualificationMatrix` / `AutonomousQualificationCase`
(`crates/economy/chio-autonomy/src/model.rs:532`) with outcomes
`Pass | FailClosed` (`model.rs:174`), validated by
`validate_autonomous_qualification_matrix`
(`crates/economy/chio-autonomy/src/validation.rs:794`). Signing uses
`SignedExportEnvelope` (`crates/core/chio-core-types/src/receipt/lineage.rs:407`).

## In scope

1. A new pure crate `chio-econ-sim` (placement resolved in Alternatives)
   holding: economic scenario and corpus types, a deterministic campaign
   engine, the `chio.econsim.*` artifact types with validators, and
   per-scenario-class fail-closed assertions against the real economy
   validators. `#![forbid(unsafe_code)]`, no I/O, integer economics.
2. Six v1 scenario classes, each declaring its target validator, its
   expected fail-closed behavior, and its finding condition:
   `sybil-pricing-ring`, `collusion-bid-ring`, `credit-exhaustion`,
   `oracle-divergence`, `fee-structuring`, `settlement-dos`.
3. `chio.econsim.scenario-result.v1` and
   `chio.econsim.qualification-matrix.v1` schemas under
   `spec/schemas/chio-econsim/v1/`, with schema-id constants and
   conformance coverage.
4. A thin driver (a `chio econsim` CLI subcommand or an xtask) that loads
   corpora from disk, runs the engine, signs the matrix, and writes the
   bundle. Disk and key access live only here, never in the pure crate.
5. An advisory (non-blocking) CI facet under `ci-gates/`, following the
   fail-closed enumerated-manifest pattern of `ci-gates/runtime.toml`,
   promotable to blocking per scenario class.
6. Economic negative tests added to `chio-conformance` asserting the exact
   fail-closed error for each class, alongside the existing budget-split
   tests (`crates/tooling/chio-conformance/tests/budget_split_rejects_oversubscribed_siblings.rs:88`,
   `budget_split_cross_hop_rejects_amplification.rs:92`).

## Out of scope (explicit cuts)

- No changes to the economy validators. WS9 only replays them. Any breach
  is filed as a finding against the owning workstream, not patched here.
- No extension of the arena `Adversary` trait or `chio-adversarial-suite`
  with economic classes (see Alternatives). The arena substrate is reused,
  its per-step verdict model is not.
- No live money, no chain broadcast, no wall-clock. Corpora are synthetic.
  The contract freeze (`2026-07-10-agent-economy-program-design.md:115`)
  is untouched.
- No new capability claim; passing matrices evidence fail-closed behavior on
  the tested corpora, nothing broader.
- No on-chain settlement DoS modeling; `settlement-dos` targets the pure
  retry classifier, not a network.

## Design

### Adversary suite

Each scenario class is a deterministic campaign: a seeded sequence of
synthetic economic actions applied to a corpus, replayed against one real
validator, yielding an observed disposition compared to the declared
expectation. Unlike the arena's single-step `AdversaryAction`, economic
campaigns are multi-step and accumulate state, so the engine models a
campaign as an action sequence over a running integer ledger.

| Class | Target validator (path:line) | Expected fail-closed | Finding |
|-------|------------------------------|----------------------|---------|
| `sybil-pricing-ring` | `qualifies_for_tier_3` (`tier.rs:135`); `compute_marketplace_credit_limit` (`marketplace_limits.rs:82`) | single-feed flood stays tier_2; ring aggregate credit does not exceed the sum of legitimately-earned per-identity ceilings | tier_3 reached with < 2 distinct feeds, or ring credit exceeds that sum |
| `collusion-bid-ring` | `bid` / `accept` (`bidding.rs:308`, `bidding.rs:439`) | every ask binds provider authority and a reservation covering total liability; sub-ceiling and out-of-scope bids reject | an accepted bid settles without covering reservation, or a mismatched-authority ask mints |
| `credit-exhaustion` | exposure ledger (`chio-credit/src/lib.rs:83`); underwriting ceilings (`underwriting_policy_input.rs:16`) | aggregate open exposure never exceeds the subject-tier ceiling; revoked/expired facilities admit no new exposure | a campaign opens exposure above the ceiling, or a revoked facility still admits |
| `oracle-divergence` | `ensure_within_threshold` (`circuit_breaker.rs:49`) | over-threshold divergence trips the breaker; stale feeds (past `max_age_seconds` at virtual clock) reject; conversion needs signed evidence | a divergent or stale pair passes, or mixed-currency aggregates without conversion evidence |
| `fee-structuring` | `RequireApprovalAbove` (`scope.rs:300`) | cumulative spend crossing the threshold requires approval | N sub-threshold calls summing above the threshold complete with no approval token |
| `settlement-dos` | `classify_attempt` (`retry.rs:123`) | the retry envelope is bounded and converges to `DeadLetter`; backoff caps | the envelope does not converge, or dead-letter volume per receipt is unbounded |

`fee-structuring` is the class most likely to surface a genuine finding:
`RequireApprovalAbove` is a per-request constraint, so cross-call
structuring may be unguarded today. WS9 ships it as an honest probe whose
test asserts the harness detects and records the outcome, whichever way the
current code lands (see Open questions).

### Simulation harness (deterministic)

The engine is a pure function of (seed, scenario class, class parameters,
corpus), reusing the arena determinism primitives: a ChaCha20 PRNG from a
recorded `u64` seed and a fixed virtual clock, under the arena contract at
`crates/core/chio-arena/src/adversary/mod.rs:21`. All money is integer:
`MonetaryAmount` u64 minor units, basis points, integer rationals;
arithmetic saturates or fails closed and never wraps
(`2026-07-10-agent-economy-program-design.md:94`). Reputation tier scores
stay f64 because they are risk coefficients, not money, and run through the
real gate unchanged. Corpora are synthetic receipt and exposure records
addressed by a canonical-JSON manifest digest (`sha256_hex` over RFC-8785
bytes, as `promote.rs:149` does). Where a validator verifies signatures
(the bid flow at `bidding.rs:313`) the corpus carries test-key signatures;
otherwise the campaign targets the post-verification surface. The engine
owns no clock or storage, matching the pure-function discipline of
`retry.rs:5`.

### Artifacts and outputs (schema ids `chio.econsim.<artifact>.v1`)

- `chio.econsim.scenario-result.v1`. One campaign outcome. Fields:
  `schema`, `scenario_id` (class plus population), `seed` (u64),
  `corpus_manifest_digest` (sha256 hex), `requirement_ids` (spec and
  invariant anchors the class defends), `expected_disposition`
  (`FailClosed`), `observed_disposition` (`FailClosed | Breach`),
  `outcome` (`Held | Finding`, where `Finding` means observed is `Breach`),
  `notes`. This mirrors `AutonomousQualificationCase` (`model.rs:532`).
- `chio.econsim.qualification-matrix.v1`. Aggregate. Fields: `schema`,
  `profile_id`, `harness_provenance` (crate version and toolchain), and
  `cases: Vec<scenario-result>`. Validated like
  `validate_autonomous_qualification_matrix` (`validation.rs:794`):
  supported schema, non-empty `profile_id`, non-empty `cases`, unique
  scenario ids, non-empty `requirement_ids`. Signed as
  `SignedExportEnvelope<QualificationMatrix>`
  (`lineage.rs:421`). This is the external-evidence artifact.

### CI integration

Add an econsim facet manifest under `ci-gates/`, structured like
`ci-gates/runtime.toml` (`runtime.toml:1`): a fail-closed table that
enumerates exactly the v1 scenario classes, rejects an unknown class, and
carries a manifest-enumeration test that rejects a short manifest. Each
entry names the committed `chio.econsim.qualification-matrix.v1` fixture to
schema-validate and the `cargo test -p chio-econ-sim` selectors that re-run
the campaign and assert observed equals expected. The gate is advisory
(non-blocking) first, as the `runtime-attack-simulation` facet models attack
fixtures without gating unrelated work (`runtime.toml:98`, laundering docs
at `runtime.toml:107`), then promotes to blocking per class once stable. A
newly observed `Finding` opens a finding record routed to the owning
workstream; it never silently flips a matrix to green.

### Error handling

Fail-closed throughout. A corpus whose bytes do not match the recorded
`corpus_manifest_digest` aborts the run; an unknown scenario class is an
error, matching the arena's unknown-class rejection
(`crates/core/chio-arena/src/adversary/mod.rs:76`); a replay whose two runs
diverge fails the determinism gate; a missing or zero seed rejects; integer
overflow saturates or fails closed, never wraps. A validator panic on
adversarial input is itself a `Finding` (the campaign records `Breach` with
the panic captured), not a harness crash; a signing failure emits no matrix.

## Alternatives considered

1. New pure crate `crates/economy/chio-econ-sim` reusing the arena
   determinism substrate. Recommended. Invariant 4
   (`2026-07-10-agent-economy-program-design.md:104`) places new signed
   artifact families in `crates/economy/` as pure contract crates, and the
   matrices are economic evidence cited by underwriting and insurance
   consumers. The crate depends downward on `chio-reputation` (trust), the
   economy validators, and `chio-arena` rng/clock (core), so there is no
   layering inversion. The `crates/tooling/` alternative next to
   `chio-conformance` is defensible; see Open questions.
2. Extend the arena `Adversary` trait and `chio-adversarial-suite` with
   economic classes. Rejected as the home. The arena models one tool-call
   step and one guard verdict (`mod.rs:114`), refereed by the kernel-guard
   pool. Economic attacks are multi-step campaigns against pure validators
   that return typed errors, not allow/deny verdicts on a single call.
   WS9 reuses the arena's seed, clock, and bundle writer, not its
   per-step adversary model.
3. Extend `chio-autonomy`'s simulation module
   (`CapitalPoolSimulationReport`, `model.rs:389`). Rejected: it couples a
   general wind tunnel to the insurance and capital-pool domain and
   overloads a market crate with adversary logic. WS9 borrows the
   qualification-matrix shape, not the crate. `chio-conformance` stays the
   home for the boolean fail-closed assertions; `chio-econ-sim` owns the
   signed matrices and the campaign engine.

## Claim and release framing

WS9 is external evidence, not a capability claim
(`2026-07-10-agent-economy-program-design.md:150`). A passing
`chio.econsim.qualification-matrix.v1` states only that, on the named
corpora and seed, the tested validators fail closed as declared; it asserts
nothing about untested corpora, live money, or distributed truth
(`2026-07-10-agent-economy-program-design.md:121`). A `Finding` is a bug in
the owning workstream, never a claim that Chio "supports" the attacked
behavior. Matrix digests may be cited as evidence inputs by underwriting and
insurance surfaces without widening any public claim.

## Testing strategy

- Per-class fail-closed unit tests against the real validator: single-feed
  sybil flood stays tier_2; a divergent feed trips `CircuitBreakerTripped`;
  oversubscribed exposure rejects; a retryable flood converges to
  `DeadLetter`; a mismatched-authority ask fails to mint.
- Determinism gate: two runs of one seed produce byte-identical
  scenario-results and matrix, mirroring
  `crates/core/chio-arena/tests/determinism_gate.rs` and `rng_determinism.rs`.
- Corpus-digest test: mutating one corpus byte changes the manifest digest
  and the engine refuses to run.
- Schema conformance: `chio.econsim.*` fixtures validate against the
  committed schemas (invariant 5,
  `2026-07-10-agent-economy-program-design.md:110`); the matrix validator
  enforces unique ids and non-empty cases.
- `fee-structuring` ships a test asserting the harness records its outcome
  (Held or Finding) deterministically, stable whichever way the current code
  lands.
- The workspace gate passes before any phase is declared done.

## Implementation phases

1. Harness skeleton (may land in wave 2). The pure `chio-econ-sim` crate:
   scenario, corpus, and `chio.econsim.*` artifact types with validators
   and signing; the deterministic campaign engine (seeded ChaCha20, virtual
   clock, integer economics); and one reference class end to end,
   `sybil-pricing-ring` against `tier.rs:135`, whose invariant is already
   property-tested. Advisory CI facet plus determinism gate.
2. Suite breadth (wave 3). The remaining five classes with expected
   fail-closed declarations, reference corpora, and `chio-conformance`
   assertions. Any breach is filed as a finding.
3. Promotion and evidence. Per-class promotion from advisory to blocking as
   each stabilizes; publish the first signed economic-robustness matrix;
   register the matrix digest as a cited evidence input on the underwriting
   and insurance surfaces without widening a claim.

## Open questions

1. Placement: `crates/economy/chio-econ-sim` (recommended, invariant 4) vs
   `crates/tooling/chio-econ-sim` (next to `chio-conformance`). Resolve at
   Phase 1 start.
2. `fee-structuring` reality (a brief-vs-code discrepancy):
   `RequireApprovalAbove` (`scope.rs:300`) is a per-request threshold, yet
   the brief describes cross-call structuring. If no cumulative-spend
   accumulator composes the constraint across calls, the first run
   legitimately produces a Finding routed to WS1 or WS8.
3. Corpus signing: which classes need test-key-signed synthetic receipts
   (the bid flow verifies signatures at `bidding.rs:313`) versus replay at
   the post-verification surface? Decide per class in Phase 2.
4. PROTOCOL reconciliation: the matrices are evidence artifacts, not wire
   protocol messages, so invariant 5's PROTOCOL reconciliation is likely
   limited to registering the `chio.econsim` schema family rather than a
   normative wire change. Confirm with the protocol owner.
