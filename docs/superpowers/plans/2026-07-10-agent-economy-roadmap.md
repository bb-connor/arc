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
- All money is `MonetaryAmount` (u64 minor units, ISO-4217); shares and
  discounts are integer basis points; money arithmetic saturates or fails
  closed.
- Fail-closed everywhere; receipts are the only authority; evidence classes
  never silently upgrade (program invariants 1-3).
- No mainnet or public-testnet deployment, custody, or new Solidity; on-chain
  needs are family-v2 proposals (program invariant 6).
- One branch and PR per workstream phase: `chio/ws<N>-<slug>`.

## Tracks

Per the release discipline, work is separated into three tracks; mixing them
hides the dependencies that govern release.

### Track A: release gates

- RFC-0013 Phase 2 money journal (inside WS1 phases 2-4): the claim "the
  production money loop is closed" is assertable only when the always-on
  end-to-end test enforces the RFC-0013 target invariant and F68-F74 are
  closed, with the `Monetary` journal mode promoted to default after the
  nightly kill-injection soak is green.
- The web3 contract freeze and its external-assurance checklist are
  untouched by this program and continue to gate any on-chain promotion.

### Track B: implementation

- Wave 1 (substrate, parallel): WS1 First Light, WS8 Fiscal constitutions,
  WS10 Comptroller Console.
- Wave 2 (markets, after WS1 Phase 1 and alongside WS1 phases 2-4): WS3
  Verified-outcome pricing, WS2 Chio Paper, WS4 Clearinghouse, WS6 Credit
  bureau. Artifact families may land offline-first; production money
  movement waits for the WS1 phase that wires it.
- Wave 3 (advanced rails): WS5 Micro-escrow channels, WS7 Parametric
  insurance. The WS9 harness skeleton may land during Wave 2.

### Track C: external evidence

- WS9 economic wind tunnel matrices (advisory CI gate first, promotable per
  scenario class) become the citable robustness evidence for underwriting
  and insurance claims.
- WS6 cross-issuer credential exchange requires a partner pilot before any
  cross-org trust claim.
- Comptroller market-position thresholds remain unproved; nothing in this
  program advances that claim.

## Wave schedule and exit gates

### Wave 1

Entry: specs approved on this branch.

- WS1 phases: 1 seams and fail-closed corrections (F68 routing consumer,
  F72 currency-mismatch deny, `economy` config block, three `configure_*`
  functions, default-closed invariant); 2 durable money journal and sweeper
  (F70, F71, F73, F74) behind the `Monetary` journal mode; 3 production
  settlement hook, async settlement runtime, credit IOU driver, adapter and
  oracle installation (F69); 4 always-on end-to-end proof and journal
  default flip after soak.
- WS8 phases: artifact family and pure resolver; fallback wiring at the four
  consumer call sites (never-brick invariant tests); amendment lifecycle and
  ladder class `fiscal.amendment_activate`.
- WS10 phases: spend event stream over the receipt query surface plus
  receipt-store cost columns; threshold webhooks; burn-rate projections and
  anomaly detectors; underwriting signal wiring.

Exit gate: WS1 Phase 4 green (release-gate claim assertable); WS8 resolver
live at all four call sites with fallback tests; WS10 stream, webhooks, and
at least the amplification detector feeding `derive_underwriting_signals`.

### Wave 2

Entry: Wave 1 exit gate, except artifact-only phases which may start after
WS1 Phase 1.

- WS3: predicate vocabulary and verdict metadata; kernel predicate
  evaluation (resolving the finalize-path guard threading risk); outcome
  billing and capture/release integration; SLA breach evidence and penalty
  path.
- WS2: `chio-factor` artifacts and assignment log; discount pricing over
  underwriting inputs; venue and penalty integration; ladder class
  `factor.assignment_bind`.
- WS4: `chio-clearing` engine and artifacts; round orchestration endpoints;
  reconciliation binding through WS1 surfaces; ladder class
  `clearing.round_finalize`.
- WS6: `chio-fincred` credential family; issuance and passport bundling;
  verifier policy and underwriting import path.

Exit gate: all four artifact families conformance-covered and CLI-exposed;
every production money movement path routes through WS1 surfaces; PROTOCOL
and CHIO_LADDER reconciled for the new families and action classes.

### Wave 3

Entry: Wave 2 exit gate.

- WS5: channel artifacts and state machine; post-persist channel metering
  driver; close and dispute handling over existing windows and watchdogs;
  family-v2 proposal document for atomic on-chain close (proposal only).
- WS7: `chio-parametric` policy and trigger evaluation; auto-claim assembly;
  payout intent and reconciliation binding; n-of-m adjudication panels and
  ladder classes.
- WS9: `chio-econ-sim` harness and six scenario classes; signed scenario
  results and qualification matrices; advisory `ci-gates/` facet.

Exit gate: channels shipped off-chain with bound and dispute tests;
parametric tier live against replayed corpora; WS9 advisory gate emitting
signed matrices on a schedule.

## Cross-program checkpoints

- RFC-0003 boot recovery: RFC-0013 registers its boot reconcile into
  RFC-0003's orchestration. Decision recorded: WS1 Phase 2 lands a minimal
  standalone boot-reconcile entry point for the payment journal unless
  RFC-0003 has landed first; revisit at Phase 2 start. This is the top
  sequencing risk (WS1 spec, open question 1).
- Reliability plans already under `docs/superpowers/plans/` (rfc-0002,
  rfc-0006, rfc-0007, rfc-0011) share kernel surfaces with WS1; rebase WS1
  phase branches over their merges rather than the reverse.

## Program decision log (from spec open questions)

- WS2: ship fraud penalties on the existing `FraudulentListing` abuse class
  first; the dedicated `FraudulentAssignment` variant lands as a coordinated
  open-market revision in the same wave.
- WS3: the budgeted finalize path does not run the post-invocation guard
  pipeline today; threading that evaluation in is a named Phase task, not an
  assumption.
- WS4: whether clearing settlement packets extend the commerce
  settlement-packet family or form a sibling family is a normative
  PROTOCOL 6.3.4 edit decided at WS4 phase 1 with a spec diff in the PR.
- WS7: rate-trigger corpus completeness needs an anchor-epoch attestation;
  design lands with the trigger evaluation phase, not after.
- WS9: crate placement defaults to `crates/economy/chio-econ-sim` per
  program invariant 4; `tooling/` remains a recorded alternative.
- WS10: receipt-store cost columns ship as a generated column plus index,
  and the stale claim in `docs/reference/AGENT_ECONOMY.md` 3.5.3 is
  corrected in the same PR.
- WS1: IOU issuer identity (kernel signing backend vs dedicated
  `economy.credit.issuer` key) is decided at WS1 Phase 3 start; the config
  block reserves the field either way.

## Detailed plan index

| Plan | Covers | Status |
|------|--------|--------|
| `2026-07-10-ws1-first-light-phase1.md` | WS1 Phase 1 (seams, F68, F72) | written |
| WS1 phases 2-4 | journal, drivers, e2e proof | at phase start |
| WS8, WS10 phase plans | Wave 1 | at workstream start |
| WS2, WS3, WS4, WS6 phase plans | Wave 2 | at wave start |
| WS5, WS7, WS9 phase plans | Wave 3 | at wave start |

Each plan follows superpowers:writing-plans (bite-sized TDD tasks, exact
paths, complete code in steps, fixed commit messages) and inherits the
Global Constraints above.
