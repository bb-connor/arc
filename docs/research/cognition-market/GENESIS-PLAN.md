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
  epoch, operator seat roster) are pure and depend on `chio-core-types` plus
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
| G0 | Program spec + executable runway model | this design set + ADR-0018 (Proposed); versioned harvest/commissioned model with all inputs | - | now (this branch) |
| G1a | `chio-genesis` crate types | pure artifact types + fail-closed validators for the four families; NO schema registration (each registers at its owning milestone) | G0, finding M1 | after finding M1 |
| G1b | Procurement list surface | schema registration; governance publish + member-nomination demand sourcing (k distinct member orgs) + control-plane search; staleness/removal | G1a, finding M2 | after M2 |
| G2 | Coverage-mining floor path | pool custody convention; floor admission gate (venue acceptance recipe + mode-A burn + BondBacked + class rule + sampled audit); release-by-default floor escrow; royalty-right registration + accrual (declared, zero live flow) | G1b, finding M2, M4, M5 | after M5 |
| G3 | Reliability epoch (r feed) | committed population and sampling; post-cutoff seed; terminal receipt roots; fixed-window Wilson rows | G2, finding M5 | after M5 |
| G4 | Operator seats | `chio.genesis.operator-seat-roster.v1`; locally enforced caps; evidence-backed roster transitions; neutrality covenant | G1a, finding M2 (declare), M7 (cross-org) | after M2; cross-org after M7 |
| G5 | Clearing fee (D7) + CCV + genesis demonstration | D7 fee; gross-principal CCV by currency; separate fee/carve metrics; related-party exclusion; public first trade | G1a, finding M2, M4 | after G1a + M4 |
| G6 | Royalty live flow + qualification + permissionless turn | ordinary royalty legs; optional distinct batch action; D7 split; retraction wiring; bounded-matrix + CLAIM_REGISTRY; permissionless design completed now and activation qualified on safety evidence | G3, G4, G5, finding M5, M6, M9; #974 | after G5 + M9 |

## 3. Per-milestone definition

### G0 Program spec (this branch)

Deliverables: GENESIS-PROGRAM.md, GENESIS-ARCHITECTURE.md, ADR-0018 (Proposed),
THREAT-MODEL.md section 7 additions, this plan, README reading-order update, and
an executable runway model covering harvest and commissioned supply. Exit: docs
gate green (`scripts/check-chio-owned-v1-only.sh` clean, no em dashes); model
self-check green; ADR-0018 in the ADR index. No pool amount or carve default is
approved from prose-only scenarios.
- Before a funding decision, commit one reviewed input snapshot beside the
  model naming an owner and evidence reference for every non-zero assumption.
  No configuration framework or simulation service is needed.

### G1a `chio-genesis` crate types (after finding M1)

- New leaf crate `crates/economy/chio-genesis` mirroring `chio-finding` style:
  pure types + fail-closed validators, no storage, no I/O. Start in one
  `src/lib.rs`; split only when the repository hygiene gate requires it.
- Types: `ProcurementList` + entries, `RoyaltyRight`, `ReliabilityEpoch` + rows,
  `OperatorSeatRoster` + seat entries + `GenesisVertical` enum, all
  `deny_unknown_fields`, INLINE
  signature per the chio-finding convention (a `signature` field over the
  canonical body with `signature` cleared; NO `SignedExportEnvelope` wrapper,
  ADR-0018 D1).
- NO schema registration here (review finding: registering ahead of an
  owning milestone is the exact #1025 M0 anti-pattern, and it would also
  touch `registry.json` inside the pre-#974 freeze). Each schema registers at
  its owning milestone: procurement-list at G1b, royalty-right at G2,
  reliability-epoch at G3, operator-seat-roster at G4.
- Content-addressed id (`compute_*_id`) and validators mirror `chio-finding`'s
  `compute_finding_id` / `validate`.
- Reuse `chio-core-types` canonical JSON (`src/canonical.rs:119`), SHA-256
  (`src/hashing.rs:119`), and `MonetaryAmount`
  (`src/capability/scope.rs:54`). Do not add Genesis hashing, money, or signature
  abstractions.
- Exit: workspace gate green; unit tests cover every fail-closed rejection per
  family; unregistered draft fixtures (including `.v999` negatives) round-trip
  and reject as specified; zero edits under `spec/schemas/`.
- Add one schema-dispatching `chio genesis verify <artifact>` command after the
  four validators exist; do not duplicate issue/publish logic in the CLI.

### G1b Procurement list surface (after finding M2)

- Registers `chio.genesis.procurement-list.v1` (its owning milestone).
- Governance-published list: `POST /v1/genesis/procurement-list` restricted to
  the governance charter signer (reuse the namespace-owner signature check
  pattern, `chio-listing/src/util.rs:27`); sellers are read-only.
- Demand sourcing at launch = SIGNED MEMBER DEMAND NOMINATIONS
  (GENESIS-ARCHITECTURE 3.1.1; raw search telemetry gates nothing, it is
  stateless, unpriced, and unattributable): `POST
  /v1/genesis/demand-nominations` restricted to identified consortium member
  keys; a descriptor is admitted only after `min_distinct_nominating_orgs`
  DISTINCT
  member orgs have nominated it; the list publishes coarse `demand_bucket`s,
  never raw counts or nominator identities. The authenticated request binds
  venue, epoch, descriptor digest, org id, signer, nonce, freshness, and
  evidence refs; entries commit `nomination_set_root`; quorum deduplicates by
  org, not key.
- Staleness/removal: `stale_after` on each entry (half-life idiom,
  `chio-pheromone/src/validation.rs:782`); `saturated` descriptors removed so the
  pool stops paying solved coverage; each republish links `previous_list_id`,
  increments exactly once, and verifies its signer under the named charter.
- Exit: an integration test publishes a governance-signed list, rejects a
  seller-signed publish, rejects a non-member nomination, admits a descriptor
  only after `k` distinct member-org nominations, rejects replay and
  cross-venue/epoch reuse, verifies the nomination-set root, rejects a forked or
  skipped list epoch, and removes a saturated descriptor; gate green.

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
  incorrect audit blocks the signature and the deadline `refund` returns the
  floor to the pool. A system-incomplete audit releases only at the deadline
  and records an operator SLA failure. Non-EVM profile: the same shape as a settle-mediated
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
  venue-ASSIGNED auditor of a scheduled random audit. G3 freezes the population
  and auditor roster plus the external checkpoint source/finality policy, then
  uses the first policy-matching unpredictable finalized checkpoint after
  cutoff; under the JOINT bound `s + beta <= 0.8` where `s` is
  the challenger slash share (binding for zero-harmed-party slashes), with the
  top-up never exceeding metered replay cost plus a bounded premium (the GA9
  self-slash-farming bounds, GENESIS-PROGRAM 4.2).
- Exit: an integration test admits a floor only on the full gate, denies a
  same-epoch duplicate-descriptor second floor, denies a mode-B floor, denies
  a `metered_attested` floor at launch, mints a royalty-only right through the
  second door, releases an UNSAMPLED floor by default at window end, releases
  a sampled-passing floor early, deadline-refunds a sampled-incorrect floor,
  and deadline-releases a system-incomplete floor while recording an operator
  SLA failure; a self-slash ring simulation nets
  negative under the published `s + beta` bound; gate green. Stop-loss: G2's
  exit report includes the first hit-conversion, conversion-efficiency, and
  security-self-funding-ratio readings against the 9.1 thresholds.

### G3 Reliability epoch / r feed (after finding M5)

- `chio.genesis.reliability-epoch.v1` registered here (its owning milestone);
  previous-epoch link, authorized roster/key, expiry, committed population,
  sampler digest, precommitted checkpoint-source/finality policy, post-cutoff
  checkpoint ref and canonical seed, assignment and
  terminal receipt roots, confidence level, and rows `{ corpus, seller,
  guarantee_class, correct, incorrect, incomplete, n_assigned, r_bps,
  r_lcb_bps }` (the LCB is what consumers read).
- Reliability computation: dedicated fixed-window binomial estimator in
  `chio-genesis`; no time decay. Missing, timed-out, and integrity-invalid audit
  outcomes count as incomplete denominator trials and operator SLA failures,
  not automatic seller fraud.
- Implement the exact hash-sort recipe in GENESIS-ARCHITECTURE 3.3: canonical
  population leaves, integer ceiling sample count, domain-separated external
  seed, related-party-excluded auditor selection, and complete assignment root.
- Control-plane surface `GET /v1/findings/reliability/{feed}/epoch`; epoch
  ticking + anchoring on operator cron (`AnchorAutomationJob` idiom, K9).
- Exit: integration tests reproduce assignments from the committed population
  and post-cutoff external seed, reject an operator-authored or policy-mismatched
  checkpoint and alternate-source selection, fail closed
  on an omitted outcome, recompute every
  Wilson row, reject count-total mismatch, forked/skipped/stale epochs, and
  cross-class reads, and show a low-`n` row weak; gate green.

### G4 Operator seats (declare after finding M2; cross-org after M7)

- `chio.genesis.operator-seat-roster.v1` registered here; each epoch includes
  the full seat set, vertical caps, and `previous_roster_id`, so validators
  enforce the cap locally.
- Enforce `epoch = previous + 1`, terminal-state monotonicity, immutable earned
  terms, and a new `seat_id` for changed economics or identity. Add the operator
  settlement binding and joint carve-policy reference.
- Revocation wiring: a governance `Sanction`/`Freeze` receipt is evidence for a
  signed prior-to-next roster transition; it does not itself revoke the seat.
  On-chain `deactivateOperator` is a separate required side effect.
- Neutrality covenant bound to the F6 obligation; cross-org realization gated on
  the M7 operator-model decision.
- Fee eligibility requires a signed clearing service-evidence reference matching
  one active roster entry per vertical; an idle seat earns nothing.
- Exit: integration tests reject a cap+1 roster and invalid prior-to-next
  transition, accept evidence-backed revocation plus operator deactivation,
  and lapse a seat on change of control pending re-grant; gate green.

### G5 Clearing fee (D7) + CCV + genesis demonstration (after finding M4)

- Ratify the additive sibling
  `chio.registry.market-clearing-fee-schedule.v1` rather than mutating the
  existing market-fee schedule. It binds that schedule id plus
  `clearing_fee_bps`, `operator_spread_bps`, `genesis_carve_policy_ref`, and the
  integer rounding rule beside
  `crates/economy/chio-open-market/src/fee_schedule.rs:71`.
- D7 clearing-fee introduction (ADR-0018 D7): a small ad-valorem venue take on
  each finding purchase, collected at reveal settlement as an ordinary
  metered/settled charge (the M2 publication-fee machinery pattern), with
  `operator_spread` retained and the remainder the splittable base; shipped as
  an additive fee-schedule sibling RATIFIED by the finding-market fee-schedule owners
  (a cross-program dependency, not assumed). No fee means no royalty
  denominator, but paid principal can still produce gross CCV.
- Add `GenesisClearingBreakdown` validation in `chio-genesis` and serialize it
  through existing `FinancialReceiptMetadata.cost_breakdown`
  (`chio-core-types/src/receipt/economics.rs:33,55`) with embedded discriminator
  `chio.genesis.clearing-breakdown.v1`. It binds every amount and
  schedule/roster/service reference needed to recompute the split.
- CCV computation: gross purchase principal by reporting window and currency,
  with separate fee revenue, carve payouts, clearing count, and unique-pair
  measures. Count all arm's-length paid clearings; exclude related parties via
  signed org/member identity and disclosed common-control/funding/operator
  relations. Treat `root_budget_holder` only as a same-root signal.
- CCV report pins methodology, currency/window, settlement and relationship
  roots, included/excluded roots, exclusion reasons, and unclassified volume;
  anchor the report root with `AnchorAutomationJob` rather than adding a fifth
  Genesis artifact family.
- Add `chio genesis ccv --from --to --currency` as a thin caller of the same
  report function used by the control-plane handler.
- Genesis demonstration: a scripted first trade (our seller swarm lists, our
  buyer swarm buys) producing a public, receipt-backed artifact set (finding
  signature, delivery receipt, settlement leg), labeled self-dealing and EXCLUDED
  from CCV; CCV counts from the first external arm's-length clearing.
- Exit: arithmetic tests prove seller principal is intact, buyer total and all
  fee legs sum exactly, absence of the sibling implies no D7 fee, and overflow/currency mismatch
  fail closed. The demonstration is excluded; related and unclassified trades
  are excluded from CCV; an external arm's-length trade is counted; gate green.

### G6 Royalty live flow + qualification + permissionless turn (after G5 + M9; #974)

- Settle royalty legs (ADR-0018 D5): v1 opens ordinary single-beneficiary legs.
  Any batching is a distinct fee-distribution action that reuses bond-impair
  invariants and is reviewed as additive EVM contract/router surface.
- Fee-split at collection: once the D7 clearing fee exists (G5) on the M2/M5
  collection machinery, the collecting operator splits per the royalty table
  and current seat roster; forward-only. The royalty validator enforces its own
  schedule ceiling; the settlement validator alone enforces the joint carve cap
  after selecting service-eligible seats.
- Qualification: bounded-matrix entries + feature-flag removal for qualified
  surfaces; CLAIM_REGISTRY approved-claim rows plus `audited_assumption` rows for
  the new trusted roles (subsidy-pool operator T5, royalty-split operator T6,
  reliability-oracle operator T7); ADR-0018 Proposed -> Accepted.
- Permissionless turn: its architecture and Sybil defenses are designed now;
  activation remains qualification-gated on Sybil, custody, and recipient
  controls, not on proof of existing demand. Market telemetry sizes parameters;
  it does not decide whether the idea is worth building.

## 4. Verification and formal hooks

- Every milestone ends on the workspace gate plus its own integration test named
  in its exit criteria.
- Formal-hook candidates (scoped inside their milestone, following the
  proof-manifest process, `formal/proof-manifest.toml`): royalty-forward-only (a
  royalty leg never references a settled trade; Kani over the leg builder, G6);
  floor-admission soundness (a floor release implies the full gate; Kani, G2);
  seat-roster cap and transition validity (Kani, G4); CCV related-party
  exclusion using the signed relationship model (bounded model, G5). These
  extend the finding-market candidates (THREAT-MODEL 6/7).

## 5. Decision backlog (future ADRs, written when their milestone starts)

| ADR | Decision | Milestone | Current lean |
|---|---|---|---|
| ADR-0018 | The four Genesis surfaces (this ADR) | G0 | Proposed |
| ADR-H | Batched fee-distribution action for royalty legs | G6 | reuse impair invariants; additive contract/router surface if batching is justified |
| ADR-I | Seat allocation under the permissionless profile (auction vs reputation gate) | post-G6 | reputation-gated; auction risks the token boundary and stays out of scope |
| ADR-J | On-chain subsidy pool (trustless custody) | post-G6 | needs the deferred ADR-0015 Follow-up A recipient allowlist; off-chain operator-custodied until then (K1/K10) |
| ADR-K | Capture-delay custody for royalties (if bonds underprice finalized fraud) | data-driven | inherits the finding-market ADR-G lean (no clawback in v1, K2) |

## 6. Risk register (program-level)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Exhaustion before demand (Q1) | unknown | program value | executable harvest/commissioned model; per-mine stop-loss; audit-rate step-downs and commissioned-production caps |
| Zombie regime: pool survives but organic supply/fees never take over (9.1 conclusion 3) | unknown | program value | exit criterion is organic takeover, not pool solvency; organic-listing-share and security-self-funding indicators alarm it; genesis window `T_g` hard-stops indefinite subsidy |
| Fee collection (M2/M5) or #974 slips | medium | royalty + seat live flow slips | artifacts declare against the table with zero flow until collection lands; G1a/G4 declaration work is independent |
| Too few member demand nominations to source a list (Q3) | medium | G1b weak | k floor tunable; wedge contexts (CI failures) are dense; fall back to curated seed descriptors with the same admission gate |
| Adverse selection subsidizes unverifiable R&D inventory (Q6) | high for R&D | pool waste | ship the royalty-only and reliability path now; treasury floor requires an adjudicable guarantee profile, not demand proof; abandonment expected |
| Permissionless Sybil (GA3) | high (permissionless) | limits activation of the later profile | design now; activate at G6 only after explicit Sybil hardening qualification |
| Operator-seat neutrality abuse (GA7) | medium | trust in seated verticals | covenant + evidence-backed next-roster revocation + separate operator deactivation; equivocation anchoring |
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
