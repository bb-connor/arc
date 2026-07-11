# Agent Economy Program Roadmap

> **For agentic workers:** This is the program coordination plan, not an
> executable task plan. Detailed per-phase plans live beside it (see the
> plan index below) and follow superpowers:writing-plans; execute those with
> superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Sequence the ten agent-economy workstreams (WS1-WS10, specs under
`docs/superpowers/specs/2026-07-10-*`) so the production money loop closes
first, market capability lands on top of it, and every claim stays inside
the bounded release posture.

**Source specs:** `2026-07-10-agent-economy-program-design.md` plus the ten
WS specs it indexes.

## Global Constraints (inherited by every per-phase plan)

- Workspace gate before any phase is declared done: `cargo build --workspace
  && cargo test --workspace && cargo clippy --workspace -- -D warnings &&
  cargo fmt --all -- --check`.
- No `.unwrap()` / `.expect()` in new code including tests (workspace lints
  deny them). No em dashes anywhere. Conventional commits.
- All money is `MonetaryAmount` (u64 minor units, ISO-4217); shares and margins
  are integer basis points, while discounts retain their owning consumer's
  declared unit (including WS8 per-hundred discounts); commitment arithmetic is
  checked and fails closed on overflow.
- Fail-closed everywhere. Capabilities plus policy and guard decisions are
  pre-action authority; receipts are signed post-action evidence. Evidence
  classes never silently upgrade (program invariants 1-3).
- No mainnet or public-testnet deployment, production custody claim, or new
  Solidity. Existing devnet escrow/vault admin, token-allowlist, and pause trust
  assumptions remain explicit; this program adds no privileged lane. On-chain
  changes are family-v2 proposals gated on external assurance (program invariant
  6 and corrected ADR-0015).
- Pure contract code performs no I/O. Chain I/O is web3-feature-gated; HTTP
  webhook, oracle, PSP, and rail I/O uses the typed `HttpEgressContract`.
- New crates require an ownership and dependency boundary. Reuse an existing
  owning crate when it already fits.
- Every signed family exits a phase only with runtime/CLI registry parity,
  unknown-family/schema/version negatives, signed positive and tampered
  verifier fixtures, and reconciled claim/release-truth gates.
- No wave exits with an unresolved Critical or High finding in its scope.
- No `n_of_m` action activates without a production FROST verifier and a
  trusted active roster, group key, key epoch, and rotation rules. `main` has no
  such Rust verifier today; test signers and independent endorsements do not
  satisfy this gate.
- One branch and PR per workstream phase: `chio/ws<N>-<slug>`.

## Tracks

Per the release discipline, work is separated into three tracks; mixing them
hides the dependencies that govern release.

### Track A: release gates

- RFC-0006 is on `main`. RFC-0003 must land before WS1 Phase 2; its durable
  dispatch-intent and boot-recovery contract is not replaceable by a standalone
  payment reconciler.
- RFC-0013 Phase 2 money journal (inside WS1 phases 2-4): the claim "the
  production money loop is closed" is assertable only when the always-on
  end-to-end test enforces the RFC-0013 target invariant and F68-F74 are
  closed, with the `Monetary` journal mode promoted to default after the
  nightly kill-injection soak is green. Because the ladder class
  `settle.commitment` is `n_of_m`, that claim is also blocked until the global
  production FROST prerequisite is met and exercised by the end-to-end test.
- The web3 contract freeze and its external-assurance checklist are
  untouched by this program and continue to gate any on-chain promotion.

### Track B: implementation

- Wave 1 (substrate): WS1 closes real fail-closed defects, then builds the
  RFC-0013 journal on landed RFC-0003; WS8 resolves governed parameters; WS10
  ships the indexed read-only spend stream first.
- Wave 2 (bounded market pilot): define and verify the canonical obligation
  and exclusive-disposition contract before any WS2-WS5 production
  integration. Pilot WS3 artifacts, pre-dispatch eligibility binding, and the
  pure `ZeroCharge` evaluator with a small deterministic predicate vocabulary.
  No current in-tree adapter qualifies for `HoldCapture`, so payment activation
  remains blocked on a real reversible rail and its qualification. No current
  generic tool server proves provider-owned durable acceptance either, so the
  output-priced path also waits for the signed, restart-queryable acceptance
  transport and zero unresolved-handoff gate. WS6 ships
  issuer-authenticated, imported/asserted credentials. WS2 and WS4 stay
  artifact-only until their ownership and deduplication gates pass.
- Wave 3 (advanced rails): production WS2 and WS4 integration, WS5 channels,
  and WS7 insurance start only after their named evidence and exclusivity
  gates pass. WS9 begins as ordinary regression tests and internal
  qualification.

### Track C: external evidence

- Project-signed WS9 matrices are internal qualification. They become citable
  external evidence only when an independent runner or witness signs a
  provenance-complete corpus and run for the stated claim scope.
- WS6 cross-issuer credential exchange requires a partner pilot before any
  cross-org trust claim. A home authority's signature authenticates its own
  report but does not turn that report into objective or independently
  verified truth; receivers preserve its imported/asserted evidence class.
- Comptroller market-position thresholds remain unproved; nothing in this
  program advances that claim.

## Wave schedule and exit gates

### Wave 1

Entry: specs approved on this branch; RFC-0006 confirmed on `main`.

- WS1 phases: 1 only real fail-closed behavior (F68 routing consumer and F72
  currency-mismatch deny); 2 durable money journal and sweeper (F70, F71,
  F73, F74) behind the `Monetary` journal mode, starting only after RFC-0003
  lands; 3 the configuration fields and `configure_*` functions together with
  the production settlement hook, async settlement runtime, credit IOU
  driver, adapter, and oracle they actually install (F69); 4 always-on
  end-to-end proof and journal default flip after soak. No Phase 1 no-op
  configuration seam is an exit artifact.
- WS8 phases: 1 artifact family, fixed-point money math, schemas, and parity; 2
  amendment lifecycle and pure resolver; 3 persistence plus non-activating
  propose/admit/approve/preview commands; 4 all five consumer adapters, both
  open-market issuance gates, an atomic readiness record, then activation and
  rotation plus ladder class `fiscal.amendment_activate`. No Phase 3 command may
  set `ever_activated`.
- WS10 phases: 1 pure contracts and schemas; 2 a full-`u64` order-preserving
  derived cost key, authenticated tenant sequence/time projections, index, and
  read-only spend event stream; 3 exact-window burn-rate/anomaly reports and
  deterministic underwriting merge; 4 tenant-admin, ordered, leased durable
  threshold webhooks. The cost index belongs to WS10 Phase 2 and is not deferred
  to WS1.

Exit gate: WS1 Phase 4 green (release-gate claim assertable), including the
canonical obligation and exclusive-disposition contract from Phase 3, with
one receipt-writer transaction consuming any carried RFC-0003 intent and
committing the receipt, applicable obligation sidecars, and attempt-zero observer work before
observers; WS1 Phase 3 settlement-reliability due-time/obligation indexes,
signed same-cutoff checkpoints, range/boundary/absence proofs, and restart/tamper
negatives green; WS8
  Phase 4 resolver live through all five adapters with fail-closed
  last-known-good tests and the activation-before-readiness negative green;
WS10 indexed read-only stream green. Webhooks and detector-to-underwriting
wiring may follow without blocking the substrate exit.

### Wave 2

Entry: Wave 1 exit gate. In particular, the canonical
`chio_credit::obligation` contract and `chio-store-sqlite` implementation from
WS1 Phase 3 must already satisfy program invariant 11: original/current creditor and debtor
binding, stable identity, source authority and receipt digests, duplicate
rejection, and authenticated compare-and-swap transitions among exactly one of
`per_call`, `assigned`, `channelized`, or `clearing_reserved`. WS2-WS5 may do
design work before this gate, but no production integration or independently
invented obligation type may land.

- WS3: a bounded `chio_listing::outcome` artifact/evaluator pilot with
  `chio.outcome.eligibility.v1`, a small deterministic JSON Pointer vocabulary,
  verdict metadata, and kernel predicate evaluation. The eligibility record and
  its digest commit atomically with the RFC-0003 dispatch intent. Capture/release
  activation is not a Wave 2 exit artifact: `X402PaymentAdapter` is prepaid and
  `X402PaymentAdapter`/`AcpPaymentAdapter` capture/release is local bookkeeping.
  A real reversible rail must be implemented and pass idempotency, query,
  binding, release, and end-to-end qualification before the output-stage payment
  hook can activate. The provider path must independently pass durable enqueue,
  signed acceptance, restart-query, acceptance-time index, and lost-ack
  ambiguity qualification; neither gate substitutes for the other.
- WS2: direct `chio_credit::factor` CAS assignment; discount pricing over
  underwriting inputs; obligor acknowledgement; ladder class
  `factor.assignment_bind`. Venue and penalty integration are deferred.
  Production assignment waits for payee-bound source receipts, fresh outstanding
  evidence, and shared non-equivocation.
- WS4: `chio_credit::clearing` engine and artifacts; round orchestration endpoints;
  reconciliation binding through WS1 surfaces; ladder class
  `clearing.round_finalize`. Its inputs are canonical obligations, not IOU or
  exposure summaries counted beside their source rows. Finalization remains
  disabled in this wave and while the production FROST prerequisite is absent.
- WS6: `chio.fincred.*` credential family; issuance and passport bundling;
  verifier policy and underwriting import path that preserves home-issued
  facts as imported/asserted unless independently corroborated. Reliability VC
  issuance is gated on a fresh verified WS1 Phase 3 checkpoint/range proof; no
  bounded bundle or table scan satisfies the gate.

Exit gate: canonical obligation invariants proven under duplicate and
concurrent-transition negatives; all four artifact families satisfy the
registry, unknown-schema, verifier-fixture, PROTOCOL, CHIO_LADDER, and claim
gates; every production money movement path routes through WS1 surfaces; no
Critical or High finding remains unresolved.

### Wave 3

Entry: Wave 2 exit gate.

- WS2: activate assignment and factoring over canonical obligations only after
  creditor binding, fresh outstanding evidence, and shared non-equivocation
  pass; route settlement through WS1 and preserve exclusive `assigned`
  disposition until resolution.
- WS4: activate clearing rounds over obligations atomically reserved in the
  `clearing_reserved` disposition only after the production FROST prerequisite;
  enforce quorum-gated immutable settlement intents with separate reconciliation
  and reject any summary artifact
  counted beside its source obligations.
- WS5: channel artifacts and state machine; pre-dispatch capacity reservation
  and exclusive channel disposition; close and dispute handling over existing
  windows and watchdogs; keep quorum-authorized close disabled until the same
  production FROST prerequisite is met;
  family-v2 proposal document for atomic on-chain close (proposal only).
- WS7: `chio.parametric.*` policy and trigger evaluation; auto-claim assembly;
  deterministic claim identity, atomic contest lifecycle, aggregate policy
  coverage reservation, unique payout intent and reconciliation binding;
  single-adjudicator artifacts may land before FROST, but n-of-m
  adjudication-panel supersession and settlement dispatch remain disabled until
  their production quorum prerequisites pass.
- WS9: implement the six scenario classes as ordinary tests first. A thin
  deterministic runner may later emit project-signed internal qualification
  matrices; the advisory `ci-gates/` facet cannot launder them into external
  evidence. Before Phase 3 or Wave 3 exit, `AE-CREDIT-ADMISSION-1` must land in
  `chio-credit` plus the WS1 obligation store, and
  `AE-CUMULATIVE-APPROVAL-1` must land in kernel budget/governed-intent
  admission. WS9 owns their diagnostic reruns, not those production validators.

Exit gate: WS2 assignment and WS4 clearing production paths preserve exclusive
obligation disposition and reconcile through WS1, with WS4 finalization proven
through the production FROST verifier; channels ship a devnet-funded off-chain
state machine over the existing qualified escrow, with quorum close enabled
  only through that verifier; the parametric tier is live against
  completeness-proven replayed corpora with claim/contest CAS and aggregate
  coverage non-equivocation, while panel supersession is optional and
  remains disabled without its trusted roster/key epoch; both named admission
  controls are live and their WS9 scenarios run rather than report `NotRun`;
  WS9 tests are green with no unresolved Critical or High finding. Scheduled
  project-signed matrices are
optional internal artifacts, not an exit substitute.

## Cross-program checkpoints

- RFC-0003 boot recovery: RFC-0013 registers its boot reconcile into
  RFC-0003's orchestration. RFC-0006 is already on `main`; WS1 Phase 2 is
  blocked until RFC-0003 lands. No standalone boot-reconcile entry point may
  waive or replace that dependency.
- Reliability plans already under `docs/superpowers/plans/` (rfc-0002,
  rfc-0006, rfc-0007, rfc-0011) share kernel surfaces with WS1; rebase WS1
  phase branches over their merges rather than the reverse.

## Program decision log (from spec open questions)

- Authority/evidence: capabilities plus policy and guards authorize before
  action; receipts attest the decision and outcome afterward. Later economic
  actions require fresh authority.
- Obligation routing: WS2-WS5 share one canonical obligation identity and one
  exclusive durable disposition. Summary artifacts never count beside their
  source obligations.
- Boundaries: pure crates do no I/O; chain I/O is web3-feature-gated; HTTP
  egress uses `HttpEgressContract`; new crates require a real ownership and
  dependency boundary.
- WS2: ship fraud penalties on the existing `FraudulentListing` abuse class
  first; the dedicated `FraudulentAssignment` variant lands as a coordinated
  open-market revision in the same wave.
- WS3: the budgeted finalize path does not run the post-invocation guard
  pipeline today; threading that evaluation in is a named Phase task, not an
  assumption.
- WS3 rail and dispatch gates: artifacts, eligibility binding, and the pure
  evaluator may land first. No production outcome-priced payment path activates
  until a real reversible rail and a provider-authenticated durable-acceptance
  transport both pass their WS3 qualification matrices; no current in-tree
  adapter or generic tool server does.
- WS4: clearing uses the sibling `chio.clearing.settlement-intent.v1` family.
  The existing commerce settlement packet is order/merchant/PSP-specific and
  carries mutable reconciliation fields, so it is not extended. PROTOCOL 6.3.4
  records the sibling intent plus separate reconciliation families in Phase 1.
- FROST: a separately reviewed production verifier plus trusted roster, group
  key, key epoch, and rotation semantics is a hard activation prerequisite for
  `settle.commitment`, WS4 finalization, WS5 quorum close, and WS7 panel
  supersession. No workstream silently implements or mocks that prerequisite.
- WS7: rate-trigger corpus completeness needs an anchor-epoch attestation;
  design lands with the trigger evaluation phase, not after. Parametric claims
  use deterministic identity, contest CAS, and one aggregate policy-coverage
  ledger before any payout intent can dispatch; the shared panel schema is
  `chio.adjudication.panel-decision.v1`.
- WS9: begin with ordinary tests in the owning validator crates. Add a runner
  or crate only when shared campaign code proves a distinct ownership and
  dependency boundary. Project-signed output remains internal qualification.
  Missing-target results are explicit `NotRun`; the two named production
  admission controls must land before Wave 3 exits.
- WS10: a Rust-derived eight-byte big-endian cost key plus sequence/time indexes
  ships in WS10 Phase 2, preserving the full `u64` domain, and the stale claim in
  `docs/reference/AGENT_ECONOMY.md` 3.5.3 is corrected in the same PR.
  Exact-window analytics require the time-index proof; threshold delivery uses
  ordered authority cursors and a leased durable outbox. Webhook mutation
  requires tenant-admin/write authority plus operator-approved egress.
- WS6: financial verification uses a sibling policy, local trust registry, and
  explicit v1/v2 passport carriers; cross-org presentation stays asserted.
- WS8: fiscal admission is signed and locally anchored; consumer adapters retain
  the declared live units and exact parity domains, with the documented
  fixed-point precision correction. Activation remains unavailable until the
  current runtime registry proves every consumer and issuance gate installed,
  preserving one active authority after migration.
- WS1: IOUs use a dedicated `economy.credit.issuer` backend distinct from the
  kernel receipt signer. Remote reconcile reuses the control-plane token and
  exact-authority egress seam.

## Detailed plan index

| Plan | Covers | Status |
|------|--------|--------|
| `2026-07-10-ws1-first-light-phase1.md` | WS1 Phase 1 (real F68/F72 behavior) | written |
| WS1 phases 2-4 | journal, drivers, e2e proof | at phase start |
| WS8, WS10 phase plans | Wave 1 | at workstream start |
| WS2, WS3, WS4, WS6 phase plans | Wave 2 pilot and artifact contracts | at wave start |
| WS2/WS4 production, WS5, WS7, WS9 phase plans | Wave 3 | at wave start |

Each plan follows superpowers:writing-plans with focused TDD tasks, exact paths,
concrete verification commands, and scoped conventional commits, and inherits
the Global Constraints above.
