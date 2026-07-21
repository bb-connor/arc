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

- The royalty and operator-seat fee-share LIVE FLOW (both G6) are gated on the
  D7 clearing fee (a genesis-introduced category, ADR-0018 D7, owning
  milestone G5) and on the collection machinery the finding-market plan builds
  at M2 (publication fee) and M5 (dispute fee), all of which assume #974 has
  merged and been rebased (PLAN section 0). The rights themselves are DECLARED
  earlier (royalty at G2, seats at G4) with zero flow.
- The Genesis ARTIFACT types (procurement list, royalty right, reliability
  epoch, operator seat) are pure and depend on `chio-core-types` plus
  `chio-finding` (for the guarantee-class vocabulary), so G1a is executable
  once finding M1 lands; G1a makes NO registry edits (registration waits for
  each schema's owning milestone), which also keeps it clear of the
  registry.json freeze PLAN section 0 imposes until #974 merges.

## 1. Dependency edges into the finding-market ladder (Q7)

Which finding-market milestone gates which mine:

| Genesis need | Gated by (PLAN.md) | Why |
|---|---|---|
| Findings exist to be mined | M0, M1 | no coverage without a finding artifact |
| Floor admission (BondBacked, publication-fee spam floor) | M2 | the bond-proof admission gate and publication-fee collection are M2 |
| Real clearings (for CCV, royalty semantics, the genesis demo) | M3, M4 | the digest gate (M3) and the wedge purchase E2E (M4) are what make a clearing happen |
| Audit outcomes (the input to `r`) AND the floor path's sampled audits | M5 | the challenge/audit lane and dispute-fee collection are M5; G2's floor path samples audits, so G2 depends on M5 too (review finding GA-R3b) |
| Retraction interaction with royalties | M6 | a retracted finding stops accruing forward (status feed is M6); consumed by G6 |
| Cross-org operator seats / F6 neutrality in practice | M7 | the cross-org escrow operator model is decided at M7 |
| Buyer SDK consuming `r` and the elicitation ceiling | M8 | informational edge: the consumer is finding-M8's own SDK work reading G3's published epochs, not a Genesis milestone |
| Release claims for Genesis surfaces | M9 | qualification, CLAIM_REGISTRY, RC entries are M9 |

## 2. Genesis milestone ladder

Each milestone is independently shippable and independently STOPPABLE; a stop
after any leaves the repo better documented and no production surface half-wired.
Stop-loss is explicit because the exhaustion boundary is real (GENESIS-PROGRAM
9.1).

| G | Name | One-line scope | Depends on | Executable when |
|---|---|---|---|---|
| G0 | Program spec | this design set + ADR-0018 (Proposed) | - | now (this branch) |
| G1a | `chio-genesis` crate types | pure artifact types + fail-closed validators for the four families; NO schema registration (each registers at its owning milestone) | G0, finding M1 | after finding M1 |
| G1b | Procurement list surface | schema registration; governance publish + member-nomination demand sourcing (k distinct member orgs) + control-plane search; staleness/removal | G1a, finding M2 | after M2 |
| G2 | Coverage-mining floor path | pool custody convention; floor admission gate (venue acceptance recipe + mode-A burn + BondBacked + class rule + sampled audit); release-by-default floor escrow; royalty-right registration + accrual (declared, zero live flow) | G1b, finding M2, M4, M5 | after M5 |
| G3 | Reliability epoch (r feed) | `chio.genesis.reliability-epoch.v1`; stratified reliability computation; control-plane epoch surface; cron ticking | G2, finding M5 | after M5 |
| G4 | Operator seats | `chio.genesis.operator-seat.v1`; charter per-vertical cap; Sanction revocation wiring; neutrality covenant | G1a, finding M2 (declare), M7 (cross-org) | after M2; cross-org after M7 |
| G5 | Clearing fee (D7) + CCV + genesis demonstration | D7 clearing-fee introduction (fee-schedule extension, finding-market ratification); CCV methodology + control-plane report; related-party exclusion; scripted first agent-to-agent trade as a public receipt-backed event | finding M2, M4 | after M4 |
| G6 | Royalty live flow + qualification + permissionless turn | settle royalty-leg generalization (D5); D7 fee-split at collection; retraction-stops-accrual wiring; bounded-matrix + CLAIM_REGISTRY; permissionless-profile evaluation gated on wedge telemetry | G5, finding M5, M6, M9; #974 | after G5 + M9 |

## 3. Per-milestone definition

### G0 Program spec (this branch)

Deliverables: GENESIS-PROGRAM.md, GENESIS-ARCHITECTURE.md, ADR-0018 (Proposed),
THREAT-MODEL.md section 7 additions, this plan, README reading-order update. No
wiring. Exit: docs gate green (`scripts/check-chio-owned-v1-only.sh` clean, no em
dashes); ADR-0018 in the ADR index.

### G1a `chio-genesis` crate types (after finding M1)

- New leaf crate `crates/economy/chio-genesis` mirroring `chio-finding` style:
  pure types + fail-closed validators, no storage, no I/O.
- Types: `ProcurementList` + entries, `RoyaltyRight`, `ReliabilityEpoch` + rows,
  `OperatorSeat` + `GenesisVertical` enum, all `deny_unknown_fields`, INLINE
  signature per the chio-finding convention (a `signature` field over the
  canonical body with `signature` cleared; NO `SignedExportEnvelope` wrapper,
  ADR-0018 D1).
- NO schema registration here (review finding: registering ahead of an
  owning milestone is the exact #1025 M0 anti-pattern, and it would also
  touch `registry.json` inside the pre-#974 freeze). Each schema registers at
  its owning milestone: procurement-list at G1b, royalty-right at G2,
  reliability-epoch at G3, operator-seat at G4.
- Content-addressed id (`compute_*_id`) and validators mirror `chio-finding`'s
  `compute_finding_id` / `validate`.
- Exit: workspace gate green; unit tests cover every fail-closed rejection per
  family; unregistered draft fixtures (including `.v999` negatives) round-trip
  and reject as specified; zero edits under `spec/schemas/`.

### G1b Procurement list surface (after finding M2)

- Registers `chio.genesis.procurement-list.v1` (its owning milestone).
- Governance-published list: `POST /v1/genesis/procurement-list` restricted to
  the governance charter signer (reuse the namespace-owner signature check
  pattern, `chio-listing/src/util.rs:27`); sellers are read-only.
- Demand sourcing at launch = SIGNED MEMBER DEMAND NOMINATIONS
  (GENESIS-ARCHITECTURE 3.1.1; raw search telemetry gates nothing, it is
  stateless, unpriced, and unattributable): `POST
  /v1/genesis/demand-nominations` restricted to identified consortium member
  keys; a descriptor is admitted only after `k_anonymity_floor` DISTINCT
  member orgs have nominated it; the list publishes coarse `demand_bucket`s,
  never raw counts or nominator identities.
- Staleness/removal: `stale_after` on each entry (half-life idiom,
  `chio-pheromone/src/validation.rs:782`); `saturated` descriptors removed so the
  pool stops paying solved coverage; each republish is a monotone epoch.
- Exit: an integration test publishes a governance-signed list, rejects a
  seller-signed publish, rejects a non-member nomination, admits a descriptor
  only after `k` distinct member-org nominations, and removes a saturated
  descriptor; gate green.

### G2 Coverage-mining floor path (after finding M5)

- Off-chain pool custody convention: the bonded venue operator holds the pool;
  a runbook documents the custody and the receipt-auditable outflow (no
  on-chain pool; K1/K10, GENESIS-ARCHITECTURE 4).
- Floor custody per admitted floor rides the existing escrow terminal states
  (GENESIS-PROGRAM 4.1): depositor = pool operator, beneficiary = seller,
  deadline = audit-window end plus cadence margin; floors RELEASE BY DEFAULT
  at window end via the operator-signed path binding the admission receipt
  hash, or early on a sampled passed audit's receipt hash
  (`releaseWithSignature`, `contracts/src/ChioEscrow.sol:199-228`); a sampled
  FAILING audit blocks the signature and the deadline `refund` returns the
  floor to the pool. Non-EVM profile: the same shape as a settle-mediated
  hold.
- Floor admission gate (all five): descriptor match against the G1b list
  INCLUDING the entry's pinned context and venue-authored acceptance recipe
  (the audit executes the venue's recipe, never the seller's; GA-R4); the
  descriptor's `required_guarantee_class` satisfied (launch:
  `deterministic_replay` only, the determinism rule); mode-A proof-of-burn
  (evidence receipts verify fail-closed and cost is checkable); `BondBacked`
  slashable listing (the M2 gate); the sampled-audit window per the custody
  bullet (the sampled audit IS an ordinary M5 challenge run by the venue,
  which is why G2 depends on M5).
- Contested-descriptor ordering: among concurrently admissible findings the
  floor goes to the earlier ANCHORED COMMITMENT (anchor order as tie rule),
  reusing MECHANISMS 3's settled ordering; one floor per descriptor per
  coverage epoch (a stale-then-uncovered descriptor may earn a new floor).
- Floor amount: `min(schedule(d), kappa * evidence_cost_verified)`; a mode-B
  finding's cost caps at 0 (no floor until audited).
- Royalty-right registration (its owning milestone) and accrual: mint a
  `chio.genesis.royalty-right.v1` at EITHER admission door (floor admission,
  or royalty-only admission for non-replayable classes); declared table, zero
  live flow until G6; non-transferable with change-of-control lapse.
- Audit-bounty top-up rules published with the schedule: top-ups pay ONLY the
  venue-ASSIGNED auditor of a scheduled random audit (assignment seeded from
  epoch-root randomness), under the JOINT bound `s + beta <= 0.8` where `s` is
  the challenger slash share (binding for zero-harmed-party slashes), with the
  top-up never exceeding metered replay cost plus a bounded premium (the GA9
  self-slash-farming bounds, GENESIS-PROGRAM 4.2).
- Exit: an integration test admits a floor only on the full gate, denies a
  same-epoch duplicate-descriptor second floor, denies a mode-B floor, denies
  a `metered_attested` floor at launch, mints a royalty-only right through the
  second door, releases an UNSAMPLED floor by default at window end, releases
  a sampled-passing floor early on the audit receipt, and deadline-refunds a
  sampled-failing floor to the pool; a self-slash ring simulation nets
  negative under the published `s + beta` bound; gate green. Stop-loss: G2's
  exit report includes the first hit-conversion, conversion-efficiency, and
  security-self-funding-ratio readings against the 9.1 thresholds.

### G3 Reliability epoch / r feed (after finding M5)

- `chio.genesis.reliability-epoch.v1` registered here (its owning milestone);
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
  issue, enforces a neutrality-violation Sanction that flips the seat to
  revoked, and lapses a seat on a change-of-control event pending re-grant;
  gate green.

### G5 Clearing fee (D7) + CCV + genesis demonstration (after finding M4)

- D7 clearing-fee introduction (ADR-0018 D7): a small ad-valorem venue take on
  each finding purchase, collected at reveal settlement as an ordinary
  metered/settled charge (the M2 publication-fee machinery pattern), with
  `operator_spread` retained and the remainder the splittable base; shipped as
  a fee-schedule extension RATIFIED by the finding-market fee-schedule owners
  (a cross-program dependency, not assumed). No fee, no CCV, no royalty
  denominator.
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

### G6 Royalty live flow + qualification + permissionless turn (after G5 + M9; #974)

- Settle royalty-leg generalization (ADR-0018 D5): generalize the exact-sum
  distribution beyond bond-impair for batched royalty legs, reviewed with the
  settle lane owner; single-leg royalties use the existing single-beneficiary
  release unchanged.
- Fee-split at collection: once the D7 clearing fee exists (G5) on the M2/M5
  collection machinery, the collecting operator splits per the royalty and
  seat tables; forward-only.
- Qualification: bounded-matrix entries + feature-flag removal for qualified
  surfaces; CLAIM_REGISTRY approved-claim rows plus `audited_assumption` rows for
  the new trusted roles (subsidy-pool operator T5, royalty-split operator T6,
  reliability-oracle operator T7); ADR-0018 Proposed -> Accepted.
- Permissionless turn: evaluated only here and only if wedge telemetry shows
  coverage converts (the adverse-selection residual, 9.2); the permissionless
  Sybil hardening (GA3 residual) and an on-chain pool (the deferred ADR-0015
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
| Exhaustion before demand (Q1) | unknown | program value | leading indicators (9.1) wired into G2/G5 exit reports; per-mine stop-loss; the exhaustion driver is the standing audit bill, so audit-rate step-downs are published with the schedule |
| Zombie regime: pool survives but organic supply/fees never take over (9.1 conclusion 3) | unknown | program value | exit criterion is organic takeover, not pool solvency; organic-listing-share and security-self-funding indicators alarm it; genesis window `T_g` hard-stops indefinite subsidy |
| Fee collection (M2/M5) or #974 slips | medium | royalty + seat live flow slips | artifacts declare against the table with zero flow until collection lands; G1a/G4 declaration work is independent |
| Too few member demand nominations to source a list (Q3) | medium | G1b weak | k floor tunable; wedge contexts (CI failures) are dense; fall back to curated seed descriptors with the same admission gate |
| Adverse selection subsidizes dead R&D inventory (Q6) | high for R&D | pool waste | wedge-first; R&D coverage gated on wedge conversion telemetry; abandonment expected |
| Permissionless Sybil (GA3) | high (permissionless) | limits the later profile | permissionless deferred to G6 with explicit Sybil hardening prerequisites |
| Operator-seat neutrality abuse (GA7) | medium | trust in seated verticals | covenant + Sanction/deactivate revocation; equivocation anchoring |
| CCV gamed by self-dealing (GA8) | medium | headline-metric integrity | related-party exclusion + genesis-demo labeling; CCV from first external trade |

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
