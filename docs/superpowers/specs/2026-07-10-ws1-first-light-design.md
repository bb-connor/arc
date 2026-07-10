# WS1 Design: First Light (production money loop)

- Date: 2026-07-10
- Program: agent-economy program, wave 1 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: none (program substrate)
- Claim track: implementation + release gate (RFC-0013 Phase 2)
- Branch: chio/ws1-first-light off main

## Goal

Every money plug point between the kernel and the economic crates is closed in
production, and moved funds imply either an attested receipt or a loud
reconciliation incident. Today the budget store is the only production-wired
plug point; the settlement hook, payment adapters, price oracle, and credit
driver are installed only by tests, and the settlement outcome is dropped at
its single production call site. WS1 wires all four, lands the RFC-0013 Phase 2
durable money journal that closes findings F68-F74, and proves the loop with one
always-on kernel end-to-end test running the production code paths.

## Context (what exists today)

The kernel assembles its stores through `chio-control-plane` `configure_*`
functions that each take a `(local_db_path, control_url)` pair, install a SQLite
store locally or a remote store, and are mutually exclusive. Only budgets are
covered: `configure_budget_store` (`crates/platform/chio-control-plane/src/lib.rs:527`)
sits beside `configure_receipt_store` (`:388`) and is chained from the CLI runtime
at `crates/products/chio-cli/src/cli/runtime.rs:46`. There is no `configure_*`
for settlement, payment, oracle, or credit.

The kernel exposes setters with no control-plane callers:
`set_settlement_observer` (`crates/kernel/chio-kernel/src/kernel/construction.rs:485`),
`set_payment_adapter` (`:429`), and `set_price_oracle` (`:433`). The charge path
already consumes these fields when present. `check_and_increment_budget`
(`crates/kernel/chio-kernel/src/kernel/validation.rs:775`) durably debits the
worst-case hold via `authorize_budget_hold` (`:810`);
`finalize_budgeted_tool_output_with_cost_and_metadata` (`:927`) reconciles it
(`reconcile_budget_charge` `:906`, called `:1025`), captures or releases through
`self.payment_adapter` (`:1038-1046`), and resolves cross-currency cost through
`self.price_oracle` (`resolve_cross_currency_cost` `:1216`, oracle call `:1230`).
The tool reports actual cost via `invoke_with_cost`
(`crates/kernel/chio-kernel/src/runtime.rs:288`; default `None` charges
`max_cost_per_invocation`).

The settlement machinery is fully built and unwired. The `SettlementHook` trait
(`crates/economy/chio-settle/src/hook.rs:247`) classifies a `SettlementObservation`
into `SettlementOutcome::{Accepted, Skipped, Retryable, Permanent}` (`:122`); the
observer slot `run_observer` (`crates/kernel/chio-kernel/src/kernel/settlement_observer.rs:161`)
returns `SettlementObserverStatus` (`:33`). The only implementations are test hooks.
The production defect is F68: `record_chio_receipt` binds the observer status to
`_settlement_status` and drops it (`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:185`).
The credit side is equally dark: `CreditEvaluatorHook` (`crates/economy/chio-credit/src/hook.rs:130`)
mints a signed `IouEnvelope` (`:94`), `LocalCreditAccount` implements it
(`crates/economy/chio-credit/src/local_account.rs:83`), and `SqliteIouEnvelopeStore`
(`crates/platform/chio-store-sqlite/src/iou_store.rs:42`) persists it, but nothing
in the kernel references any of it. The real `X402PaymentAdapter`/`AcpPaymentAdapter`
(`crates/kernel/chio-kernel/src/payment.rs:205`/`:219`) and the `ChioLinkOracle`
(`crates/economy/chio-link/src/lib.rs:258`) never run live.

`RFC-0013` (`docs/architecture/reliability/RFC-0013-money-path-durability.md`) is
the normative source for the durability layer: the payment journal (F70), hold
sweeper (F71), settlement routing (F68), production driver seam (F69), fail-closed
currency mismatch (F72), durable EIP-3009 nonce store (F73), and `BudgetEnforcer`
caveat (F74). `chio-config` has no economic fields today: `ChioConfig`
(`crates/platform/chio-config/src/schema.rs:11`) carries `kernel`, `adapters`,
`edges`, `receipts`, `logging`, `telemetry`, `guards`, `wasm_guards` only.

## In scope

1. An `economy` configuration block in `chio-config` (`schema.rs`) with
   `settlement`, `payment`, `oracle`, and `credit` sections, every field defaulted
   so an absent block reproduces today's behavior exactly.
2. Control-plane `configure_settlement`, `configure_payment_rail`, and
   `configure_price_oracle` functions mirroring `configure_budget_store`, chained
   into the CLI runtime after the existing `configure_*` calls.
3. A production `SettlementHook` installed in the observer slot (routing only) plus
   an async settlement runtime that writes local reconciliation records and
   optionally dispatches to the trust-control reconcile surface.
4. A credit driver in that runtime evaluating persisted receipts into signed
   `IouEnvelope` values through the production `CreditEvaluatorHook` and
   `IouEnvelopeStore`.
5. The RFC-0013 Phase 2 durable money journal (F70), hold sweeper (F71),
   settlement routing consumer (F68), production driver seam (F69), fail-closed
   currency mismatch (F72), durable EIP-3009 nonce store (F73), and
   `BudgetEnforcer` caveat and snapshot seam (F74), following RFC-0013's design.
6. One always-on kernel end-to-end test driving quote, governed commit, metered
   execution, settlement observation, and credit IOU minting through a live kernel
   with production wiring (mock rail endpoints acceptable, production code paths
   mandatory).

## Out of scope (explicit cuts)

- Any mainnet or public-testnet deployment, custody, on-chain settlement dispatch,
  or new Solidity. The default settlement driver makes no chain calls. The
  `StablecoinPaymentAdapter` and on-chain settlement remain family-v2 proposals
  gated on external assurance (program invariant 6, ADR-0015).
- Refund or charge reversal. ADR-0006's no-refund model
  (`docs/adr/ADR-0006-monetary-budget-semantics.md:86`) keeps `total_cost_charged`
  monotone; the journal records and reconciles rail movement without inventing a
  refund the kernel does not own.
- RFC-0003's generic dispatch-intent journal. WS1 owns only the monetary
  specialization; the `receipt XOR open_intent` safety predicate stays with RFC-0003
  (see Open questions on the boot-recovery dependency).
- Distributed-linearizable spend truth (the ADR-0006 HA overrun bound at `:67`
  stands), and new market artifact families (WS2-WS10). WS1 is substrate only.

## Design

### Components

- Config: `EconomyConfig` under `ChioConfig.economy` (`crates/platform/chio-config/src/schema.rs`),
  with `settlement { driver, store, control_url, control_token }`,
  `payment { rail, endpoint, timeout_ms, auth }`, `oracle` (the existing
  `PriceOracleConfig` shape), and `credit { store, issuer }`. Every section is
  `#[serde(default)]`; `deny_unknown_fields` stays enforced.
- Control-plane wiring: `configure_settlement`, `configure_payment_rail`, and
  `configure_price_oracle` (`crates/platform/chio-control-plane/src/lib.rs`), each a
  `(local_db_path, control_url)`-mutually-exclusive assembler installing through the
  existing setters. No new kernel setters are needed for settlement, payment, or oracle.
- Production settlement hook (observer slot): a reconciling `SettlementHook` in
  `chio-settle` (`ops.rs`) that `configure_settlement` installs through
  `set_settlement_observer`. Its `observe` classifies the observation and returns
  `Accepted`/`Retryable`/`Permanent`/`Skipped`, doing only bounded work: it never
  re-reads a receipt or mints an IOU on the post-persist path, because the slot
  contract forbids blocking dispatch on hook latency (`construction.rs:481`).
- Settlement runtime (F69, `settlement.driver = { none, ops }`, default `none`): the
  async workhorse over persisted receipts. It scans priced allow receipts lacking an
  `iou_envelope`/`settlement_reconciliations` row, mints exactly one `IouEnvelope`
  via a `LocalCreditAccount` seeded through `new_with_trusted_kernel_keys`
  (`crates/economy/chio-credit/src/local_account.rs:64`) with the kernel signing
  identity, persists it idempotently through `IouEnvelopeStore`
  (`crates/economy/chio-credit/src/store_binding.rs:48`), writes the reconciliation
  record (`crates/platform/chio-store-sqlite/src/receipt_store/reports/reconciliation.rs:29`),
  and re-runs `classify_and_persist` (`crates/economy/chio-settle/src/retry.rs:123`)
  on failure. Records are local by default; a configured `control_url` additionally
  dispatches to `POST /v1/settlements/reconcile` (`docs/reference/AGENT_ECONOMY.md:753`).
  On-chain dispatch is never on this path. Unsigned, untrusted-signer, or zero-price
  receipts mint nothing (`crates/economy/chio-credit/src/hook.rs:132`).
- Durability layer: the RFC-0013 `payment_journal` state machine (`HoldPlaced ->
  Authorized -> Settling -> Settled -> Closed`, or `ReconcileFailed`), boot
  reconciliation, the open-hold sweeper, the F68 routing consumer
  (`route_settlement_observer_status` + `classify_and_persist` + `settle_attempts`),
  the F72 currency-mismatch deny, the F73 nonce store, and the F74 snapshot seam.
  These follow RFC-0013 verbatim; implementation-cycle decisions are recorded here.

### Data flow

1. Quote. A cross-currency draft resolves a rate through the installed
   `PriceOracle` (`resolve_cross_currency_cost`, `validation.rs:1216`), attaching
   `OracleConversionEvidence`. Same-currency drafts skip the oracle.
2. Governed commit. Capability validation succeeds; `authorize_budget_hold`
   durably debits the worst-case hold (`validation.rs:810`) and, in the same
   `Immediate` transaction, writes the `payment_journal` row in `HoldPlaced`.
   `adapter.authorize` runs, and the journal advances to `Authorized`.
3. Metered execution. The tool runs and reports actual cost via
   `invoke_with_cost` (`runtime.rs:288`).
4. Reconcile. `reconcile_budget_charge` closes the hold at the realized amount
   (`validation.rs:1025`); the journal advances to `Settling` carrying the exact
   settle intent, the adapter capture/release runs (`:1038-1046`), and the journal
   advances to `Settled`.
5. Durable receipt. `FinancialReceiptMetadata` is assembled (`validation.rs:1114`)
   and the signed receipt is persisted before the mediated `Allow` returns
   (ADR-0013 durable-before-allow, `docs/adr/ADR-0013-async-receipt-durability.md:17`);
   the journal is then closed.
6. Settlement observation. `record_chio_receipt` runs the observer outside the
   receipt-store write lock (`receipt_persistence.rs:185`) and routes its outcome
   (F68); a non-`Accepted` outcome produces a `settle_attempts` or
   `settle_dead_letters` row plus a warn and metric. The async settlement runtime
   then reads the persisted receipt, mints the credit IOU, and writes the
   reconciliation record.

### Configuration surface

The `economy` block is default-closed: an absent block installs no observer,
adapter, oracle, or driver, keeps `settlement.driver = none`, and yields
byte-identical receipts (the existing settlement-observer invariant test still
holds). Each `configure_*` rejects both a local path and a `control_url` together,
like `configure_budget_store` (`lib.rs:534`), and `control_url` requires a
`control_token` via `require_control_token` (`lib.rs:553`). The RFC-0013 `Monetary`
journal mode gates journal writes and defaults off until the soak is green.

### Error handling (fail-closed)

- A monetary call reaching a store without journal support returns
  `BudgetStoreError::Invariant`, never a silent success; a wrong `expected` state
  in `advance_payment_journal` is a `Conflict`-shaped invariant. `settlement_state`
  defaults to `PaymentError::Unavailable`, forcing a boot `ReconcileFailed`
  incident rather than a wrong close.
- `BudgetTree::evaluate` returns `Deny(CurrencyMismatch)` when a spend-capped node
  currency is absent or differs from the draft (F72), realizing ADR-0006's
  cross-currency fail-closed stance (`docs/adr/ADR-0006-monetary-budget-semantics.md:110`).
  A payment authorization present without a configured adapter stays
  `KernelError::Internal` (`validation.rs:1032`).
- IOU minting fails closed on signature, untrusted signer, or canonical-encoding
  error (`crates/economy/chio-credit/src/hook.rs:28`); `IouEnvelopeStore` rejects a
  conflicting envelope for the same `receipt_id` (`store_binding.rs:41`). Settlement
  failures never roll back dispatch or rewrite a signed receipt; settlement status
  stays advisory in `FinancialReceiptMetadata`.

## Alternatives considered

1. Settlement hook target. (A) Local reconciliation records only. (B) Dispatch
   only to the trust-control reconcile surface. (C) Local by default with optional
   remote dispatch. Recommendation: C. The `settlement_reconciliations`,
   `iou_envelope`, and `settle_dead_letters` tables the CLI `chio settle status`
   already reads (`crates/products/chio-cli/src/settle.rs:89-99`) are local, so a
   single-node deployment must work with no control plane; the remote dispatch
   reuses the existing `(local, control_url)` pattern and stays optional and
   token-gated. On-chain is excluded either way by the freeze.
2. Credit driver placement. (A) A new kernel `set_credit_evaluator` observer slot
   invoked in `record_chio_receipt`. (B) Mint the IOU inline inside the observer
   hook, loading the receipt by id. (C) Mint in the async settlement runtime over
   persisted receipts. Recommendation: C. It matches scope item (c) ("persisted
   receipts") and RFC-0013's F69 seam, and keeps the post-persist observer path
   bounded (the slot must not block dispatch, `construction.rs:481`). A is rejected
   by program invariant 4 (no new kernel business logic); B adds receipt re-read and
   signing latency before the `Allow` returns.
3. Journal rollout. (A) Ship the money journal enabled unconditionally. (B) Ship
   behind the RFC-0013 `Monetary` journal mode, default off, promoted to default
   after the nightly kill-injection soak. (C) Ship only the F68 routing consumer
   and defer the journal. Recommendation: B. It matches RFC-0013's own staged
   rollout, bounds the added per-call latency behind the highest-consequence class
   first, and keeps the release-gate claim honest until the soak proves crash
   recovery.

## Claim and release framing

WS1 is implementation within the bounded release posture plus one release gate.
The claim "the production money loop is closed" becomes assertable only when the
RFC-0013 target invariant (moved funds imply an attested receipt or a
reconciliation incident) is enforced by the always-on end-to-end test and F68-F74
are closed. Settlement and reconciliation surfaces are signed intent plus
reconciliation evidence, not custody and not finality (program invariant 7). No
public claim widens: the contract freeze and its external-assurance gate are
untouched, the ADR-0006 HA overrun bound stands, and live capital remains a
separate product track. All money is `MonetaryAmount` in u64 minor units.

## Testing strategy

- Always-on end-to-end (the release-gate proof): a kernel assembled through the
  production `configure_settlement`/`configure_payment_rail`/`configure_price_oracle`
  path with a mock rail endpoint and a static oracle, driving quote, governed
  commit, metered execution, settlement observation, and credit IOU. Asserts the
  receipt is durable before the settlement observer runs (durable-before-allow),
  exactly one signed `IouEnvelope` is persisted, a `settlement_reconciliations`
  row exists, the `payment_journal` row is `Closed`, and the budget hold reconciled
  to the realized amount. It reuses the `support_monetary` fixtures
  (`crates/kernel/chio-kernel/src/kernel/tests/support_monetary.rs`).
- Default-closed invariant: with no `economy` block, receipts are byte-identical
  and no settlement, payment, oracle, or credit code runs.
- RFC-0013 unit and property tests: journal collision fails closed;
  `advance_payment_journal` wrong-state is `Conflict`; the F72 property (no `Allow`
  when a spend-capped node currency is absent or differs); the boot-reconcile
  property (every `request_id` resolves to attested receipt, reconciliation receipt,
  or `ReconcileFailed`, never a silent non-terminal row, never a double capture);
  and a loom model of the routing consumer (no lost attempt row, no double
  dead-letter).
- Crash and soak (load-chaos program, nightly and weekly): SIGKILL between
  `authorize` and receipt commit, and between `authorize_budget_hold` and reconcile;
  assert attested-or-incident and swept capacity per RFC-0013's acceptance criteria.

## Implementation phases

Each phase is an independently landable PR ending green at the workspace gate
(`cargo build --workspace && cargo test --workspace && cargo clippy --workspace
-- -D warnings && cargo fmt --all -- --check`).

- Phase 1 (seams and fail-closed corrections). The `economy` config block; the
  three `configure_*` control-plane functions plus their CLI-runtime chaining
  (installing nothing when the block is absent); the F72 currency-mismatch deny;
  the F68 routing consumer replacing the drop at `receipt_persistence.rs:185`,
  with the `settle_attempts` table and `CHIO_SETTLEMENT_UNRESOLVED_TOTAL` metric.
  No behavior change when the economy block is unset.
- Phase 2 (durable money journal and sweeper, RFC-0013 F70/F71). The
  `payment_journal` table, `PaymentJournalState`/`PaymentJournalRecord`, the
  defaulted `BudgetStore` journal methods, the `validation.rs` state-machine
  wiring, the `PaymentAdapter` `rail_id`/`settlement_state` additions and boot
  reconcile, the open-hold sweeper (`HoldDisposition::Expired`, sweep task, CLI
  `chio budget holds` commands, metrics), plus F73 `SqliteEip3009NonceStore` and
  F74 `BudgetEnforcer` caveat and snapshot. Gated behind the `Monetary` journal
  mode, default off.
- Phase 3 (production settlement and credit driver, RFC-0013 F69). The observer-slot
  `SettlementHook` (routing only); the async `SettlementRuntime` minting IOUs and
  writing reconciliation records over persisted receipts, with optional trust-control
  dispatch, behind `settlement.driver = { none, ops }` default none; the payment
  adapter and price oracle installed from config.
- Phase 4 (end-to-end proof and gate flip). The always-on end-to-end test with
  full production wiring; promotion of the `Monetary` journal to default after the
  nightly soak is green; F68-F74 closed; the "production money loop is closed"
  release-gate claim becomes assertable.

## Open questions

1. RFC-0003 boot-recovery dependency. RFC-0013 states "RFC-0003 lands first" and
   registers its boot reconcile into RFC-0003's boot-recovery orchestration and
   `MonetaryReconciled` resolution, but the program design marks WS1
   "Depends on: none." Resolution: either Phase 2 lands a minimal standalone
   boot-reconcile entry point for the payment journal, or it sequences behind
   RFC-0003. This is the top sequencing risk.
2. IOU issuer identity. The production `LocalCreditAccount` signs IOUs whose
   `issuer_key` must match the receipt's kernel signing identity. Does
   `configure_settlement` hand the kernel signing backend to the credit driver, or
   does the driver mint with a distinct credit-issuer key surfaced in
   `economy.credit.issuer`? This is a key-management and config decision.
3. Credit-driver discovery. The async runtime completes credit-eligible receipts
   the observer already routed. Should it scan the receipt store for priced allow
   receipts lacking an `iou_envelope`/`settlement_reconciliations` row (robust,
   restart-safe, but a periodic scan), or should the F68 routing enqueue an explicit
   work row on `Accepted` (targeted, but extends RFC-0013's F68 which returns on
   `Accepted`)? The scan is the recommended default.
4. Trust-control dispatch auth. The optional remote reconcile path
   (`POST /v1/settlements/reconcile`) should reuse `configure_budget_store`'s
   `control_token` seam; confirm the driver threads that token, not a second one.
5. Checkpoint boundary in the end-to-end test. The journal and holds live in the
   budget-store database while receipts and checkpoints live in the receipt-store
   database, so the test forces a low `checkpoint_interval`
   (`crates/platform/chio-config/src/schema.rs:112`) and crosses a checkpoint
   boundary to prove durable-before-allow holds under checkpointing.
