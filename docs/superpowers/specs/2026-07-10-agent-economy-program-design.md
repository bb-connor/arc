# Agent Economy Program Design

- Date: 2026-07-10
- Program: agent-economy program (ten workstreams, three waves)
- Normative anchors: `spec/PROTOCOL.md` (5.1-5.2, 6.3.4, 9, 14), `spec/CHIO_LADDER.md` 5.2, `spec/METERING.md`, `docs/reference/AGENT_ECONOMY.md`, `docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`, `docs/architecture/reliability/RFC-0013-money-path-durability.md`, `docs/adr/ADR-0006`, `docs/adr/ADR-0015`, `contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json`
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
| WS2 | Chio Paper | `2026-07-10-ws2-chio-paper-design.md` | Receivables factoring: assignment artifacts over pending receipts and IOU envelopes, priced by underwriting, traded via listings |
| WS3 | Verified-outcome pricing | `2026-07-10-ws3-outcome-pricing-design.md` | Outcome predicates on listings, guard-attested success in receipts, escrow release bound to attested outcomes, bonds backing SLA breaches |
| WS4 | Chio Clearinghouse | `2026-07-10-ws4-clearinghouse-design.md` | Deterministic multilateral netting over exposure ledgers, signed net-position statements, batched settlement packets per counterparty epoch |
| WS5 | Micro-escrow channels | `2026-07-10-ws5-micro-escrow-channels-design.md` | Receipt-metered payment channels: bounded escrow deposit, signed cumulative channel state per receipt, dispute-window close |
| WS6 | Agent credit bureau | `2026-07-10-ws6-credit-bureau-design.md` | Financial credentials in passports: credit scorecards, exposure history, settlement reliability, premium history, selective disclosure |
| WS7 | Parametric insurance | `2026-07-10-ws7-parametric-insurance-design.md` | Coverage bound to receipt-observable trigger events with auto-assembled claim evidence, plus opt-in n-of-m adjudication panels |
| WS8 | Fiscal constitutions | `2026-07-10-ws8-fiscal-constitutions-design.md` | Economic parameters (fee schedules, tier tables, discount curves, penalty rates) as charter-scoped signed artifacts with amendment rules |
| WS9 | Economic wind tunnel | `2026-07-10-ws9-economic-wind-tunnel-design.md` | Adversarial economic arena suite and deterministic market simulations emitting signed economic-robustness qualification matrices |
| WS10 | Comptroller Console | `2026-07-10-ws10-comptroller-console-design.md` | Live spend observability: receipt-log cost streaming, budget webhooks, burn-rate projections, spend-anomaly findings feeding underwriting signals |

## Dependency graph and waves

```
Wave 1 (substrate):      WS1 First Light    WS8 Fiscal constitutions    WS10 Comptroller Console

Wave 2 (markets):        WS3 Outcome pricing     WS2 Chio Paper
                         WS4 Clearinghouse       WS6 Credit bureau

Wave 3 (advanced rails): WS5 Channels        WS7 Parametric insurance    WS9 Wind tunnel
```

Hard edges (blocking):

- WS2, WS3, WS4 production money movement depends on WS1 (settlement hook,
  payment adapter wiring, durable journal). Their artifact families and
  offline verification land independently of WS1, in the established
  economy-crate pattern.
- WS7 payout execution depends on WS4 or WS1 dispatch; its trigger and
  evidence machinery depends on WS3 (SLA breach events) only for the
  SLA-trigger class.
- WS5 on-chain close depends on WS1 and on contract-freeze posture; any new
  contract surface is a family-v2 proposal gated on external assurance and
  is out of scope for the shipped wave.
- WS9 attacks the markets, so its full adversary suite follows Wave 2; the
  harness skeleton may land during Wave 2.

Soft edges (compounding, not blocking):

- WS8 parameters are consumed by WS2, WS3, WS4, WS7 fee and penalty
  schedules; absent WS8 they fall back to operator-signed schedules.
- WS10 anomaly findings feed WS6 credentials and WS9 scenarios.
- WS6 credentials strengthen WS2 buyer-side risk pricing.

## Shared invariants (design law for every workstream)

1. Receipt authority. The signed Chio receipt is the only authorization and
   evidence truth. Every new artifact is evidence-referential and
   digest-bound to receipts or to other signed artifacts. Payment-rail,
   chain, and PSP payloads remain subordinate digest-bound evidence. No
   artifact upgrades asserted provenance to observed or verified; evidence
   classes are preserved end to end.
2. Money representation. All monetary values are
   `chio_core_types::capability::scope::MonetaryAmount` (u64 minor units,
   ISO-4217). Shares and margins are integer basis points. Exchange rates
   are integer rationals with signed `OracleConversionEvidence`. No floats
   in money math; floats stay confined to risk coefficients. Arithmetic on
   money saturates or fails closed; it never wraps.
3. Fail-closed. Verification errors deny. Invalid artifacts and policies
   reject at load time. Mixed-currency aggregation yields null totals unless
   conversion evidence is attached. Missing authority receipts reject.
4. Crate pattern. New artifact families ship as pure contract crates under
   `crates/economy/` (`#![forbid(unsafe_code)]`, no I/O, serde types plus
   deterministic validation). Persistence goes behind traits implemented in
   `platform/chio-store-sqlite`. Network and chain I/O lives only in
   web3-feature-gated runtime crates honoring the egress contract. Kernel
   integration goes through existing hook slots and `chio-control-plane`
   wiring, never through new kernel-side business logic.
5. Schema discipline. Artifacts are canonical JSON (RFC 8785), signed, with
   versioned schema identifiers (`chio.<family>.<artifact>.v1`) declared as
   constants, JSON schemas under `spec/schemas/`, and conformance coverage.
   Wire-visible changes reconcile with `spec/PROTOCOL.md` in the same
   workstream phase.
6. Freeze discipline. No mainnet or public-testnet deployment, custody, or
   promotion. Value-movement contracts keep no admin, pause, or upgrade
   lane (ADR-0015); forced closures never re-price and never pay the
   protocol. New on-chain needs are written as family-v2 proposals gated on
   the external-assurance checklist; shipped scope is devnet qualification
   only.
7. Bounded-profile honesty. Nothing in this program claims
   distributed-linearizable budget or spend truth. The HA overrun bound
   (ADR-0006) stands. Netting, channels, and settlement surfaces are signed
   intent plus reconciliation evidence, not custody and not finality claims
   beyond the documented independent-head checks.
8. Ladder anchoring. Financial action classes bind to `spec/CHIO_LADDER.md`
   5.2: facility binding and liability auto-bind stay bilateral-required;
   settlement commitments stay n-of-m quorum-required. New action classes
   introduced by a workstream are added to the ladder with an explicit
   governance mode in the same phase.
9. House rules. No em dashes anywhere. No process-narration comments.
   Conventional commits. Clippy `unwrap_used`/`expect_used` deny. The
   workspace gate (`cargo build && cargo test && cargo clippy -- -D
   warnings && cargo fmt --check`) passes before any phase is declared done.
10. Roadmap framing. Every workstream states its claim track (release gate,
    implementation, external evidence) and never widens a public claim
    implicitly. Live capital remains a separate product track.

## Claim and release framing

- Release gates. WS1 completes the RFC-0013 Phase 2 money journal; "the
  production money loop is closed" becomes claimable only when the RFC-0013
  target invariant (moved funds imply an attested receipt or a
  reconciliation incident) is enforced by an always-on kernel e2e test and
  the F68-F74 findings are closed. The contract freeze and its
  external-assurance gate are untouched by this program.
- Implementation. WS1-WS8 and WS10 are engineering within the bounded
  release posture. WS4 must not describe netting output as settlement truth;
  it emits signed net-position statements and settlement packets that the
  existing quorum-gated settlement surface consumes.
- External evidence. WS9 produces signed economic-robustness matrices, the
  evidence artifact future underwriting and insurance claims cite. WS6
  cross-issuer credential exchange requires a partner pilot before any
  cross-org trust claim. Comptroller market-position thresholds remain
  unproved and are not advanced by this program.

## Program-level risks

- Scope gravity. Ten workstreams invite parallel sprawl. Mitigation: waves
  are strict; a wave-2 workstream may land artifact crates early but may not
  wire production money movement before WS1 phases complete.
- Freeze collision. WS5 (and WS3 escrow binding) are the workstreams most
  likely to want contract changes. Mitigation: both are designed against the
  existing `ChioEscrow`/`ChioBondVault` interfaces; anything requiring new
  Solidity is explicitly deferred to a family-v2 proposal document.
- Claim drift. Insurance, credit, and clearing vocabulary reads as regulated
  activity. Mitigation: every spec carries the "signed intent and evidence,
  not custody, not insurer-of-record, not a rail" boundary language, and
  reuses the disclaimers already normative in `spec/PROTOCOL.md` 9 and 14.
- Parameter authority split. WS8 moves constants into governed artifacts;
  consumers must fail closed to their current built-in values when no valid
  fiscal artifact is present, so WS8 cannot brick pricing or penalties.
- Reliability-program coupling. RFC-0013's boot reconcile registers into
  RFC-0003's boot-recovery orchestration, so WS1's journal phase sequences
  with the reliability program even though WS1 has no dependency inside this
  program. The WS1 plan carries this as an explicit cross-program
  checkpoint.

## Process

Each workstream spec in this directory carries: grounded context,
in/out-of-scope cuts, artifact and type design, integration points,
alternatives considered with a recommendation, claim framing, testing
strategy, and milestone-level implementation phases. The program roadmap and
the detailed executable plan for Wave 1 live under `docs/superpowers/plans/`.
Detailed per-task plans for Waves 2 and 3 are written per-wave at execution
time, after the preceding wave's phase gates pass, following
`superpowers:writing-plans`.
