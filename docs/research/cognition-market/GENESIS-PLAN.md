# Genesis Coverage Program Plan

> **For agentic workers:** this is the program-level plan for the bootstrap
> layer. It DEPENDS ON but does not modify the cognition-market milestone ladder
> in [PLAN.md](PLAN.md); dependency edges into `M0`-`M9` are explicit below.
> Execution happens per-milestone through bite-sized plans authored when
> dependencies land (the #1025 rule, PLAN section 6).

**Goal:** bootstrap coverage, security, and clearing for the finding market
ahead of organic demand - without a token, on a bounded treasury,
consortium-first - per [GENESIS-PROGRAM.md](GENESIS-PROGRAM.md) and
[GENESIS-ARCHITECTURE.md](GENESIS-ARCHITECTURE.md).

**Why a sibling plan, not a PLAN.md edit.** [PLAN.md](PLAN.md) is 462 lines and
under active #1025 review; the finding-market ladder ships independently of this
program. The Genesis ladder is a distinct program whose milestones DEPEND ON the
finding-market milestones but never change them. A sibling file keeps PLAN.md
byte-stable during its review and puts every cross-program dependency in one
legible place (the edges table below). No edit to PLAN.md is required; the two
plans compose through the dependency edges.

## Global constraints (inherited)

- No token; no transferable reward unit; subsidies buy inventory or security,
  never behavior or volume (hard constraints, GENESIS-PROGRAM 2).
- No em dashes; conventional commits; fail-closed; clippy
  `unwrap_used`/`expect_used` deny; workspace gate per change
  (`cargo build --workspace && cargo test --workspace && cargo clippy
  --workspace -- -D warnings && cargo fmt --all -- --check`).
- Schema evolution: additive optional fields; new families are new schema ids
  registered at their OWNING milestone; negative fixtures use the `.v999`
  convention; `scripts/check-chio-owned-v1-only.sh` and
  `scripts/check-chio-schema-registry.sh` must pass.
- Ship dark until qualified: every Genesis surface sits behind a cargo feature
  and outside the bounded operational profile until G6.

## 0. Baseline dependency: PR #974 and fee collection

Stated up front because it gates two of the three mines. PR #974 is UNMERGED
(GENESIS-PROGRAM section 0), and fee collection is declarative-only today (K1).
Therefore:

- The royalty LIVE FLOW (G2) and the operator-seat fee-share LIVE FLOW (G4) are
  gated on real fee collection, which the finding-market plan builds at M2
  (publication fee) and M5 (dispute fee), both of which assume #974 has merged
  and been rebased (PLAN section 0).
- The Genesis ARTIFACT types (procurement list, royalty right, reliability
  epoch, operator seat) are pure and depend only on `chio-core-types`; they can
  be built now, exactly as the finding-market M0/M1 built the finding types
  ahead of the kernel work.

## 1. Dependency edges into the finding-market ladder (Q7)

Which finding-market milestone gates which mine:

| Genesis need | Gated by (PLAN.md) | Why |
|---|---|---|
| Findings exist to be mined | M0, M1 | no coverage without a finding artifact |
| Floor admission (BondBacked, publication-fee spam floor) | M2 | the bond-proof admission gate and publication-fee collection are M2 |
| Real clearings (for CCV, royalty semantics, the genesis demo) | M3, M4 | the digest gate (M3) and the wedge purchase E2E (M4) are what make a clearing happen |
| Audit outcomes (the input to `r`) | M5 | the challenge/audit lane and dispute-fee collection are M5 |
| Retraction interaction with royalties | M6 | a retracted finding stops accruing forward (status feed is M6) |
| Cross-org operator seats / F6 neutrality in practice | M7 | the cross-org escrow operator model is decided at M7 |
| Buyer SDK consuming `r` and the elicitation ceiling | M8 | the buyer helpers and pool-purchasing convention are M8 |
| Release claims for Genesis surfaces | M9 | qualification, CLAIM_REGISTRY, RC entries are M9 |

## 2. Genesis milestone ladder

Each milestone is independently shippable and independently STOPPABLE; a stop
after any leaves the repo better documented and no production surface half-wired.
Stop-loss is explicit because the exhaustion boundary is real (GENESIS-PROGRAM
9.1).

| G | Name | One-line scope | Depends on | Executable when |
|---|---|---|---|---|
| G0 | Program spec | this design set + ADR-0018 (Proposed) | - | now (this branch) |
| G1a | `chio-genesis` crate types | pure artifact types + fail-closed validators for the four families; register only procurement-list + royalty-right schemas | G0, finding M1 | now |
| G1b | Procurement list surface | governance publish + k-anonymity demand sourcing + control-plane search; staleness/removal | G1a, finding M2 | after M2 |
| G2 | Coverage-mining floor path | off-chain pool custody convention; floor admission gate (demanded-uncovered + mode-A burn + BondBacked + audit sample); escrowed floor; royalty-right accrual (declared, zero live flow) | G1b, finding M2, M4 | after M4 |
| G3 | Reliability epoch (r feed) | `chio.finding.reliability-epoch.v1`; stratified reliability computation; control-plane epoch surface; cron ticking | G2, finding M5 | after M5 |
| G4 | Operator seats | `chio.genesis.operator-seat.v1`; charter per-vertical cap; Sanction revocation wiring; neutrality covenant | G1a, finding M2 (declare), M7 (cross-org) | after M2; cross-org after M7 |
| G5 | CCV + genesis demonstration | CCV methodology + control-plane report; related-party exclusion; scripted first arm-to-arm trade as a public receipt-backed event | finding M4 | after M4 |
| G6 | Royalty live flow + qualification + permissionless turn | settle royalty-leg generalization (D5); fee-split at collection; bounded-matrix + CLAIM_REGISTRY; permissionless-profile evaluation gated on wedge telemetry | finding M5, M9; #974 | after M5/M9 + fee collection |

## 3. Per-milestone definition

### G0 Program spec (this branch)

Deliverables: GENESIS-PROGRAM.md, GENESIS-ARCHITECTURE.md, ADR-0018 (Proposed),
THREAT-MODEL.md section 7 additions, this plan, README reading-order update. No
wiring. Exit: docs gate green (`scripts/check-chio-owned-v1-only.sh` clean, no em
dashes); ADR-0018 in the ADR index.

### G1a `chio-genesis` crate types (executable now)

- New leaf crate `crates/economy/chio-genesis` mirroring `chio-finding` style:
  pure types + fail-closed validators, no storage, no I/O.
- Types: `ProcurementList` + entries, `RoyaltyRight`, `ReliabilityEpoch` + rows,
  `OperatorSeat` + `GenesisVertical` enum, all `deny_unknown_fields`, inline
  `SignedExportEnvelope` signature shape.
- Register ONLY `chio.genesis.procurement-list.v1` and
  `chio.genesis.royalty-right.v1` at this milestone (their owning milestones are
  G1b/G2); the reliability-epoch and operator-seat schemas register at G3/G4
  respectively (the #1025 discipline: no schema ahead of its milestone).
- Content-addressed id (`compute_*_id`) and validators mirror `chio-finding`'s
  `compute_finding_id` / `validate`.
- Exit: workspace gate green; registered schemas accepted by
  `validate_signed_artifact_schema`; golden fixture per registered family
  validates against schema and struct; negative `.v999` fixtures reject.

### G1b Procurement list surface (after finding M2)

- Governance-published list: `POST /v1/genesis/procurement-list` restricted to
  the governance charter signer (reuse the namespace-owner signature check
  pattern, `chio-listing/src/util.rs:27`); sellers are read-only.
- k-anonymity demand sourcing: a descriptor is admitted only after
  `k_anonymity_floor` distinct buyer clusters (`root_budget_holder`) have queried
  it; the list publishes coarse `demand_bucket`s, never raw counts.
- Staleness/removal: `stale_after` on each entry (half-life idiom,
  `chio-pheromone/src/validation.rs:782`); `saturated` descriptors removed so the
  pool stops paying solved coverage; each republish is a monotone epoch.
- Exit: an integration test publishes a governance-signed list, rejects a
  seller-signed publish, admits a descriptor only after `k` distinct clusters,
  and removes a saturated descriptor; gate green.

### G2 Coverage-mining floor path (after finding M4)

- Off-chain pool custody convention: the bonded venue operator holds the pool;
  every floor payout is an ordinary receipt-backed single-beneficiary release; a
  runbook documents the custody and the receipt-auditable outflow (no on-chain
  pool; K1/K10, GENESIS-ARCHITECTURE 4).
- Floor admission gate (all four): demanded-uncovered descriptor match against
  the G1b list; mode-A proof-of-burn (evidence receipts verify fail-closed and
  cost is checkable); `BondBacked` slashable listing (the M2 gate); passed audit
  sample.
- Floor amount: `min(schedule(d), kappa * evidence_cost_verified)`; a mode-B
  finding's cost caps at 0 (no floor until audited); at most one floor per
  descriptor (K5).
- Royalty-right accrual: mint a `chio.genesis.royalty-right.v1` at floor
  admission (declared table, zero live flow until G6/M5); non-transferable.
- Exit: an integration test admits a floor only on the full gate, denies a
  duplicate-descriptor second floor, denies a mode-B floor pre-audit, escrows the
  floor and releases it after a passing audit (clawing to the pool on a failing
  audit); gate green. Stop-loss: G2's exit report includes the first
  hit-conversion and conversion-efficiency readings against the 9.1 thresholds.

### G3 Reliability epoch / r feed (after finding M5)

- `chio.finding.reliability-epoch.v1` registered here (its owning milestone);
  rows `{ corpus, seller, guarantee_class, r_bps, n, decayed }`.
- Reliability computation: a stratified wrapper over `compute_reliability`
  (`chio-reputation/src/compare.rs:160`) scoped to audit receipts, per
  `(corpus, seller, guarantee_class)`, with mandatory `n`.
- Control-plane surface `GET /v1/findings/reliability/{feed}/epoch`; epoch
  ticking + anchoring on operator cron (`AnchorAutomationJob` idiom, K9).
- Exit: an integration test computes `r` over a mixed corpus, publishes a signed
  epoch, rejects a cross-class read (a `metered_attested` row must not be served
  as `deterministic_replay`), and shows a low-`n` row flagged; gate green.

### G4 Operator seats (declare after finding M2; cross-org after M7)

- `chio.genesis.operator-seat.v1` registered here; charter carries the per-
  vertical cap; issuer refuses to sign beyond the cap.
- Revocation wiring: `revocation_rule_ref` resolves to a governance
  `Sanction`/`Freeze` case that revokes the seat; on-chain settlement key via
  `deactivateOperator` (`contracts/src/ChioIdentityRegistry.sol:89`).
- Neutrality covenant bound to the F6 obligation; cross-org realization gated on
  the M7 operator-model decision.
- Exit: an integration test issues seats up to the cap and rejects the cap+1
  issue, and enforces a neutrality-violation Sanction that flips the seat to
  revoked; gate green.

### G5 CCV + genesis demonstration (after finding M4)

- CCV computation over settlement receipts: net-of-spread, dedup by
  `(finding_id, buyer_cluster)`, related-party exclusion via `root_budget_holder`
  (`chio-core-types/src/receipt/economics.rs:33`); control-plane
  `GET /v1/genesis/ccv` with a pinned methodology.
- Genesis demonstration: a scripted first trade (our seller swarm lists, our
  buyer swarm buys) producing a public, receipt-backed artifact set (finding
  signature, delivery receipt, settlement leg), labeled self-dealing and EXCLUDED
  from CCV; CCV counts from the first external arm's-length clearing.
- Exit: the demonstration trade verifies end-to-end and is excluded from CCV; a
  synthetic related-party trade is excluded; an external arm's-length trade is
  counted; gate green.

### G6 Royalty live flow + qualification + permissionless turn (after M5/M9 + #974)

- Settle royalty-leg generalization (ADR-0018 D5): generalize the exact-sum
  distribution beyond bond-impair for batched royalty legs, reviewed with the
  settle lane owner; single-leg royalties use the existing single-beneficiary
  release unchanged.
- Fee-split at collection: once M2/M5 collection exists, the collecting operator
  splits per the royalty table; forward-only.
- Qualification: bounded-matrix entries + feature-flag removal for qualified
  surfaces; CLAIM_REGISTRY approved-claim rows plus `audited_assumption` rows for
  the new trusted roles (subsidy-pool operator, reliability-oracle operator,
  royalty-split operator; T5/T6/T7); ADR-0018 Proposed -> Accepted.
- Permissionless turn: evaluated only here and only if wedge telemetry shows
  coverage converts (the adverse-selection residual, 9.2); the permissionless
  Sybil hardening (G3 residual) and an on-chain pool (the deferred ADR-0015
  Follow-up A allowlist) are its prerequisites.

## 4. Verification and formal hooks

- Every milestone ends on the workspace gate plus its own integration test named
  in its exit criteria.
- Formal-hook candidates (scoped inside their milestone, following the
  proof-manifest process, `formal/proof-manifest.toml`): royalty-forward-only (a
  royalty leg never references a settled trade; Kani over the leg builder, G6);
  floor-admission soundness (a floor release implies the full gate; Kani, G2);
  seat-cap monotonicity (issued seats per vertical never exceed the cap; Kani,
  G4); CCV related-party exclusion (no credit for shared-root trades; bounded
  model, G5). These extend the finding-market candidates (THREAT-MODEL 6/7).

## 5. Decision backlog (future ADRs, written when their milestone starts)

| ADR | Decision | Milestone | Current lean |
|---|---|---|---|
| ADR-0018 | The four Genesis surfaces (this ADR) | G0 | Proposed |
| ADR-H | Settle exact-sum generalization beyond impair for batched royalty legs | G6 | reuse the impair distribution invariants; thin extension, no new contract (D5) |
| ADR-I | Seat allocation under the permissionless profile (auction vs reputation gate) | post-G6 | reputation-gated; auction risks the token boundary and stays out of scope |
| ADR-J | On-chain subsidy pool (trustless custody) | post-G6 | needs the deferred ADR-0015 Follow-up A recipient allowlist; off-chain operator-custodied until then (K1/K10) |
| ADR-K | Capture-delay custody for royalties (if bonds underprice finalized fraud) | data-driven | inherits the finding-market ADR-G lean (no clawback in v1, K2) |

## 6. Risk register (program-level)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Exhaustion before demand (Q1) | unknown | program value | leading indicators (9.1) wired into G2/G5 exit reports; per-mine stop-loss |
| Fee collection (M2/M5) or #974 slips | medium | royalty + seat live flow slips | artifacts declare against the table with zero flow until collection lands; G1a/G4 declaration work is independent |
| Demanded-descriptor telemetry too thin to source a list (Q3) | medium | G1b weak | k-anonymity floor tunable; wedge contexts (CI failures) are dense; fall back to curated seed descriptors with the same admission gate |
| Adverse selection subsidizes dead R&D inventory (Q6) | high for R&D | pool waste | wedge-first; R&D coverage gated on wedge conversion telemetry; abandonment expected |
| Permissionless Sybil (G3) | high (permissionless) | limits the later profile | permissionless deferred to G6 with explicit Sybil hardening prerequisites |
| Operator-seat neutrality abuse (G7) | medium | trust in seated verticals | covenant + Sanction/deactivate revocation; equivocation anchoring |
| CCV gamed by self-dealing (G8) | medium | headline-metric integrity | related-party exclusion + genesis-demo labeling; CCV from first external trade |

## 7. Plan maintenance rules

- One bite-sized implementation plan per milestone, authored with the target
  files open (never from memory), stored in [plans/](plans/) as
  `YYYY-MM-DD-G<N>-<name>.md`, following superpowers:writing-plans, only when its
  dependencies (both Genesis and finding-market) have landed.
- Every landed Genesis milestone updates: this ladder table, the CCV/leading-
  indicator readings, and (from G6) the PROTOCOL.md genesis-family section.
- The first executable work is G1a (the `chio-genesis` crate types), directly
  analogous to the finding-market M0/M1 crate; everything else waits on its
  dependency edges.
