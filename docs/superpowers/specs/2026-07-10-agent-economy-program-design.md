# Agent Economy Program Design

- Date: 2026-07-10
- Program: agent-economy program (ten workstreams, three waves)
- Normative anchors: `spec/PROTOCOL.md` (5.1-5.2, 6.3.4, 9, 14), `spec/CHIO_LADDER.md` 5.2, `spec/METERING.md`, `docs/reference/AGENT_ECONOMY.md`, `docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`, `docs/architecture/reliability/RFC-0003-dispatch-intent-journal.md`, `docs/architecture/reliability/RFC-0013-money-path-durability.md`, `docs/adr/ADR-0006`, `docs/adr/ADR-0015`, `contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json`
- Branch strategy: one branch and PR per workstream phase (`chio/ws<N>-<slug>`), all off `main`

## Context

Chio's economic layer is three tiers sharing the receipt spine:

1. A kernel-native metered budget path that is production-wired for budgets
   only: capability cost caps, worst-case pre-charge holds, post-execution
   reconciliation, and signed receipts carrying `FinancialReceiptMetadata`.
2. A signed-artifact economic contract layer (13 crates under
   `crates/economy/`) covering listings, open-market bidding with bonds and
   penalties, underwriting, credit and IOUs, liability insurance, bounded
   autonomous pricing, metering, and billing export. It is exercised through
   the CLI and the `chio trust serve` comptroller plane, offline from the
   kernel dispatch path.
3. Web3 runtimes (`chio-anchor`, `chio-link`, `chio-settle`,
   `chio-web3(-bindings)`) with real broadcast code, qualified on local
   devnet only, under a no-mainnet freeze pending external assurance.

The production plug points between tier 1 and everything downstream are
empty: `set_settlement_observer` has no callers, no production
`SettlementHook` implementation exists, `set_payment_adapter` and
`set_price_oracle` are installed only by tests, `CreditEvaluatorHook` has no
production driver, and manifest `ToolPricing` is never read by the charge
path. RFC-0013 catalogs the resulting money-path durability gaps (F68-F74).

This program closes the loop and then builds differentiated market
capability on top of it. Each workstream has its own design spec in this
directory; this document fixes what is shared: the workstream set, the
dependency graph, the sequencing, the invariants every spec obeys, and the
claim discipline.

## Workstreams

| WS | Title | Spec | One-line scope |
|----|-------|------|----------------|
| WS1 | First Light | `2026-07-10-ws1-first-light-design.md` | Production wiring for the money loop (settlement hook, payment adapters, price oracle, credit driver) plus the RFC-0013 durable money journal and an always-on kernel e2e test |
| WS2 | Chio Paper | `2026-07-10-ws2-chio-paper-design.md` | Direct CAS assignment of canonical obligations with obligor acknowledgement, fresh outstanding evidence, and underwriting-derived discount terms; venue trading is deferred |
| WS3 | Verified-outcome pricing | `2026-07-10-ws3-outcome-pricing-design.md` | Deterministic JSON Pointer outcome artifacts and evaluator; activation waits for both a genuine reversible rail and a provider-authenticated durable-dispatch transport |
| WS4 | Chio Clearinghouse | `2026-07-10-ws4-clearinghouse-design.md` | Deterministic multilateral netting over canonical obligations, signed net-position statements, and immutable settlement intents with separate reconciliation |
| WS5 | Micro-escrow channels | `2026-07-10-ws5-micro-escrow-channels-design.md` | Payment channels with bounded pre-dispatch reservation, exclusive obligation routing, signed cumulative state, and dispute-window close |
| WS6 | Agent credit bureau | `2026-07-10-ws6-credit-bureau-design.md` | Issuer-asserted financial credentials in passports: credit scorecards, exposure history, settlement reliability, premium history, selective disclosure |
| WS7 | Parametric insurance | `2026-07-10-ws7-parametric-insurance-design.md` | Coverage bound to receipt-observable trigger events with auto-assembled claim evidence, plus opt-in n-of-m adjudication panels |
| WS8 | Fiscal constitutions | `2026-07-10-ws8-fiscal-constitutions-design.md` | Live economic inputs (fee/bond schedules, tier limits, per-hundred discounts, and two premium schedules) as charter-scoped signed artifacts with amendment rules |
| WS9 | Economic wind tunnel | `2026-07-10-ws9-economic-wind-tunnel-design.md` | Adversarial economic tests and deterministic simulations emitting project-signed internal qualification matrices |
| WS10 | Comptroller Console | `2026-07-10-ws10-comptroller-console-design.md` | Live spend observability: receipt-log cost streaming, budget webhooks, burn-rate projections, spend-anomaly findings feeding underwriting signals |

## Dependency graph and waves

```
Reliability prerequisite: RFC-0006 (landed) -> RFC-0003 -> WS1 Phase 2

Wave 1 (substrate):      WS1 First Light    WS8 Fiscal constitutions    WS10 Comptroller Console

Wave 2 (bounded pilot):  WS3 Outcome artifacts/evaluator   WS2/WS4 artifact contracts
                         WS6 Credit bureau

Wave 3 (advanced rails): WS2/WS4 production  WS5 Channels  WS7 Insurance  WS9 internal qualification
```

Hard edges (blocking):

- RFC-0006 is on `main`. RFC-0003 must land before WS1 Phase 2 starts.
  RFC-0013 is a money-path specialization of RFC-0003 and must register its
  payment reconciliation with RFC-0003 recovery; a standalone replacement is
  not an allowed shortcut.
- `spec/CHIO_LADDER.md` requires FROST for `settle.commitment` and every other
  `n_of_m` action, but `main` has no production Rust FROST verifier. Activating
  any such path is hard-gated on a separately reviewed production verifier plus
  a trusted active roster, group key, key epoch, and rotation rules. This gate
  applies to the WS1 release claim, WS4 finalization, WS5 quorum close, and WS7
  panel supersession. Artifact construction and non-quorum paths may land
  earlier; a test signer or endorsement set does not satisfy the gate.
- WS2, WS3, WS4 production money movement depends on WS1 (settlement hook,
  payment adapter wiring, durable journal). Their artifact families and
  offline verification land independently of WS1, in the established
  pure-contract pattern.
- No current in-tree payment adapter qualifies as a genuine reversible rail for
  WS3: `X402PaymentAdapter` is prepaid and both `X402PaymentAdapter` and
  `AcpPaymentAdapter` perform local capture/release bookkeeping. WS3 output-stage
  payment activation is a separate hard edge on a real networked
  hold/capture/release implementation plus idempotency, query, binding, and
  end-to-end qualification. Artifact, eligibility, and pure evaluator work may
  land while that edge remains blocked.
- No current generic in-tree tool server proves provider-owned durable
  acceptance for WS3. Outcome-priced dispatch also requires a provider-signed
  acceptance after restart-safe queueing, exact idempotency/status query, local
  acceptance-time persistence, and the RFC-0003 unresolved-handoff ambiguity
  gate. Socket acceptance or in-memory enqueue does not satisfy this hard edge.
- WS3 pre-dispatch eligibility depends on RFC-0003's additive nullable
  `outcome_eligibility_digest` and typed intent-plus-eligibility actor command.
  A digest-only intent, separately committed eligibility row, or post-dispatch
  attachment is not an allowed intermediate implementation.
- WS2-WS5 production integration also depends on the canonical obligation and
  exclusive-disposition contract in invariant 11. Artifact-only work may not
  invent a parallel ownership, creditor, exposure, or routing model.
- WS7 payout execution depends on WS4 or WS1 dispatch; its trigger and
  evidence machinery depends on WS3 (SLA breach events) only for the
  SLA-trigger class. Any payout activation also depends on its deterministic
  claim/contest state and aggregate policy-coverage reservation store.
- WS6's settlement-reliability credential depends on WS1 obligation and
  reconciliation stores exposing authenticated, boundary-complete ranges at one
  cutoff. Other WS6 credential families may land without that metric; a bounded
  source bundle cannot substitute for denominator completeness.
- WS5 on-chain close depends on WS1 and on contract-freeze posture; any new
  contract surface is a family-v2 proposal gated on external assurance and
  is out of scope for the shipped wave.
- WS9 attacks the markets, so its ordinary regression scenarios follow the
  owning validators. A shared runner waits until Wave 2 interfaces stabilize
  and shared campaign code proves a distinct boundary. Wave 3 exit additionally
  depends on the separately owned `AE-CREDIT-ADMISSION-1` and
  `AE-CUMULATIVE-APPROVAL-1` production controls and green WS9 reruns.

Soft edges (compounding, not blocking):

- None are active in v1. WS8 parameter adoption, WS10-to-WS6 credential input,
  and WS6-to-WS2 pricing were considered but are not declared by the downstream
  contracts. A later phase may add one only with an exact versioned input,
  authority resolver, evidence-class floor, activation order, and fail-closed
  fallback; this program does not imply those bindings.

## Shared invariants (design law for every workstream)

1. Authority and evidence. Before dispatch, capability validation and the
   applicable policy and guard decisions authorize or deny the proposed
   action. A receipt is the signed post-action record of the mediation
   decision and observed outcome; it is evidence, not the authority that
   permitted the action. Every new artifact is evidence-referential and
   digest-bound to receipts or other signed artifacts, and any later economic
   action must carry its own valid pre-action authority. Payment-rail, chain,
   PSP, and issuer-authored payloads remain subordinate digest-bound evidence.
   No artifact upgrades asserted provenance to observed or verified; evidence
   classes are preserved end to end.
2. Money representation. All monetary values are
   `chio_core_types::capability::scope::MonetaryAmount` (u64 minor units,
   ISO-4217). Shares and margins are integer basis points. Exchange rates
   are integer rationals with signed `OracleConversionEvidence`. No floats
   in money math; floats stay confined to risk coefficients. Arithmetic that
   creates or changes a monetary commitment is checked and fails closed on
   overflow; it never wraps or silently turns overflow into a payable cap.
3. Fail-closed. Verification errors deny. Invalid artifacts and policies
   reject at load time. Mixed-currency aggregation yields null totals unless
   conversion evidence is attached. Missing pre-action authority or required
   post-action receipt evidence rejects.
4. Boundary discipline. Reuse an existing owning crate first. A new crate is
   justified only by a distinct ownership and dependency boundary, not merely
   by a new artifact family. Pure contract code (`#![forbid(unsafe_code)]`,
   serde types, deterministic validation) performs no filesystem, clock, or
   network I/O. Persistence goes behind traits implemented in
   `platform/chio-store-sqlite`. Chain broadcast and chain RPC live only in
   web3-feature-gated runtime crates. HTTP webhook, oracle, PSP, and rail I/O
   lives in runtime or adapter crates and must use the typed
   `HttpEgressContract` with exact-authority validation, redirects denied, and
   bounded responses. Kernel integration goes through existing hook slots and
   `chio-control-plane` wiring, never through new kernel-side business logic.
5. Schema and verifier discipline. Artifacts are canonical JSON (RFC 8785),
   signed, with versioned schema identifiers
   (`chio.<family>.<artifact>.v1`) declared as constants, JSON schemas under
   `spec/schemas/`, and conformance coverage. Every signed family must land in
   the runtime and CLI registries together, with a registry-parity test,
   unknown-family/schema/version negatives, and signed positive plus tampered
   verifier fixtures. Wire-visible changes reconcile with `spec/PROTOCOL.md`
   in the same phase. No public claim advances until the claim registry,
   release-truth checks, and verifier-backed fixtures all agree.
6. Freeze discipline. No mainnet or public-testnet deployment, production
   custody claim, or promotion. The existing devnet `ChioEscrow` and
   `ChioBondVault` do hold test assets and have transferable admins, token
   allowlists, and pause controls. A pause blocks release/impairment but not the
   eventual refund/expiry path, so it is an admitted liveness and outcome trust
   assumption, not a non-discretionary guarantee. This program neither adds nor
   widens a privileged or upgrade lane. Forced closures never re-price and never
   pay the protocol. ADR-0015 records the live limitation; any new on-chain need
   or admin-model change is a family-v2 proposal gated on external assurance.
   Shipped scope is devnet qualification only.
7. Bounded-profile honesty. Nothing in this program claims
   distributed-linearizable budget or spend truth. The HA overrun bound
   (ADR-0006) stands. Netting, channels, and settlement surfaces are signed
   intent plus reconciliation evidence, not custody and not finality claims
   beyond the documented independent-head checks.
8. Ladder anchoring. Financial action classes bind to `spec/CHIO_LADDER.md`
   5.2: facility binding and liability auto-bind stay bilateral-required;
   settlement commitments stay n-of-m quorum-required. New action classes
   introduced by a workstream are added to the ladder with an explicit
   governance mode in the same phase. No `n_of_m` action activates until the
   production FROST verifier and trusted roster/group-key epoch prerequisite in
   the hard edges is satisfied.
9. House rules. No em dashes anywhere. No process-narration comments.
   Conventional commits. Clippy `unwrap_used`/`expect_used` deny. The
   workspace gate (`cargo build --workspace && cargo test --workspace && cargo
   clippy --workspace -- -D warnings && cargo fmt --all -- --check`) passes
   before any phase is declared done.
10. Roadmap framing. Every workstream states its claim track (release gate,
    implementation, external evidence) and never widens a public claim
    implicitly. Live capital remains a separate product track.
11. Canonical obligations. `chio_credit::obligation` is the sole type owner for
    `ObligationAtom`, `ObligationDisposition`, the authenticated transition
    event, and the backend-neutral store trait; `chio-store-sqlite` owns the
    durable implementation. Before WS2-WS5 production integration, the
    immutable atom must bind a stable `obligation_id`, debtor,
    `original_creditor`, amount,
    currency, due/expiry terms, pre-action authority digest, and source receipt
    digest. A receipt, IOU, exposure entry, assignment, channel update, or
    clearing packet may reference that obligation but may not mint a second
    economic claim for the same value. Each live obligation has exactly one
    durable disposition: `per_call`, `assigned`, `channelized`, or
    `clearing_reserved`. For a journaled request, the receipt-writer transaction
    also consumes the exact RFC-0003 dispatch intent; a read-only request has no
    intent. Whenever a paired observer is installed it seeds
    durable attempt-zero work for every receipt; for positive outstanding value
    it additionally
    commits the immutable atom, initial disposition, and creation event. All
    applicable rows commit atomically before any observer or downstream
    settlement path runs. Any failure leaves every projection absent and the
    dispatch intent open for recovery. Disposition changes
    append an authenticated audit event
    and update the current projection by compare-and-swap in one transaction;
    the current creditor resolves only from that disposition (`per_call` uses
    `original_creditor`; `assigned` names the acknowledged assignee); no mutable
    owner field exists on the atom. Aggregators reject duplicates and never sum
    a summary envelope alongside its source obligations. Settlement lifecycle
    remains a separate state dimension. Missing original or current creditor
    identity, fresh outstanding evidence, or exclusive disposition rejects fail
    closed.

## Claim and release framing

- Release gates. WS1 completes the RFC-0013 Phase 2 money journal; "the
  production money loop is closed" becomes claimable only when the RFC-0013
  target invariant (moved funds imply an attested receipt or a
  reconciliation incident) is enforced by an always-on kernel e2e test and
  the F68-F74 findings are closed. The contract freeze and its
  external-assurance gate are untouched by this program.
- Implementation. WS1-WS8 and WS10 are engineering within the bounded
  release posture. WS4 must not describe netting output as settlement truth;
  it emits signed net-position statements and immutable settlement intents that the
  existing quorum-gated settlement surface consumes.
- External evidence. WS9 initially produces project-signed internal
  qualification results. Those signatures authenticate the signer and bind its
  declared inputs and result; deterministic replay is established only by an
  independent rerun. They do not prove robustness, underwriting facts, or
  insurability. A WS9 result becomes external evidence only after an independent
  runner or witness signs a provenance-complete corpus and run, with the claim
  scope named explicitly. WS6 home-authority reports are
  authenticated issuer assertions; receivers preserve them as
  imported/asserted evidence unless independently corroborated. Cross-issuer
  exchange requires a partner pilot before any cross-org trust claim.
  Comptroller market-position thresholds remain unproved and are not advanced
  by this program.

## Program-level risks

- Scope gravity. Ten workstreams invite parallel sprawl. Mitigation: waves
  are strict; a wave-2 workstream may land artifact contracts early but may not
  wire production money movement before WS1 phases complete.
- Freeze collision. WS5 is the workstream most likely to want contract changes.
  Mitigation: v1 is designed against an already funded `ChioEscrow`; anything
  requiring new Solidity is explicitly deferred to a family-v2 proposal
  document. WS3 lands artifact and evaluator contracts only until both a real
  typed reversible rail and a provider-authenticated durable-acceptance
  transport are implemented and qualified.
- Claim drift. Insurance, credit, and clearing vocabulary reads as regulated
  activity. Mitigation: every spec carries the "signed intent and evidence,
  not custody, not insurer-of-record, not a rail" boundary language, and
  reuses the disclaimers already normative in `spec/PROTOCOL.md` 9 and 14.
- Parameter authority split. WS8 moves constants into governed artifacts;
  consumers may use built-in values only before the first activation. After
  activation, a missing, invalid, expired, or rolled-back artifact retains the
  last-known-good schedule or denies; it never restores looser defaults.
- Reliability-program coupling. RFC-0006 is on `main`; RFC-0003 is the hard
  prerequisite for WS1 Phase 2. RFC-0013's boot reconcile registers into
  RFC-0003's boot-recovery orchestration. No standalone reconcile substitute
  may satisfy the phase entry gate.
- Quorum substrate. Ladder policy already requires FROST for settlement
  commitments, while `main` has no production verifier. The release claim and
  every quorum action remain disabled until the hard-edge prerequisite is met;
  documentation, fixtures, or independent participant endorsements cannot be
  treated as an implementation.
- Qualification laundering. Project-generated synthetic corpora can be useful
  regressions but are not independent evidence. WS9 begins as ordinary tests
  and internal qualification, and no wave exits with an unresolved Critical or
  High finding in its scope.

## Process

Each workstream spec in this directory carries: grounded context,
in/out-of-scope cuts, artifact and type design, integration points,
alternatives considered with a recommendation, claim framing, testing
strategy, and milestone-level implementation phases. The program roadmap and
the detailed executable plan for Wave 1 live under `docs/superpowers/plans/`.
Detailed per-task plans for Waves 2 and 3 are written per-wave at execution
time, after the preceding wave's phase gates pass, following
`superpowers:writing-plans`.
