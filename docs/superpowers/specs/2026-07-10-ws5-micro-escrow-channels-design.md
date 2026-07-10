# WS5 Design: Streaming micro-escrow channels

- Date: 2026-07-10
- Program: agent-economy program, wave 3 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: WS1 (settlement wiring); contract freeze constrains on-chain scope
- Claim track: implementation
- Branch: chio/ws5-micro-escrow-channels off main

## Goal

For high-frequency small tool calls, per-call settlement is wasteful (one rail
or chain action per receipt) and `allow_then_settle`
(`spec/PROTOCOL.md:526`, `docs/reference/TOOL_PRICING_GUIDE.md:132`) defers
settlement while accumulating unbounded counterparty exposure: the payee keeps
delivering value with nothing settled and no ceiling on what is owed. WS5 adds
receipt-metered payment channels. A bounded funding reference caps the exposure;
the parties exchange signed cumulative channel states off-chain, one per metered
receipt; only the net settles once, at close. The channel is a settlement
optimization on top of the signed-receipt spine, never an authority path.

## Context

- Every allowed receipt carries `FinancialReceiptMetadata` with `cost_charged`
  and `currency` in minor units
  (`crates/core/chio-core-types/src/receipt/economics.rs:37`); money is
  `MonetaryAmount { units: u64, currency: String }`
  (`crates/core/chio-core-types/src/capability/scope.rs:54`).
- WS1 wires a post-persist observer slot: after a receipt is signed and durably
  stored, `record_chio_receipt` calls `run_settlement_observer`
  (`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:185`),
  which builds a `SettlementObservation` from the financial metadata and runs a
  registered `SettlementHook`
  (`crates/kernel/chio-kernel/src/kernel/settlement_observer.rs:129`, `:161`).
  The hook is observer-only relative to receipt bytes and its failure never
  rolls back dispatch (`crates/economy/chio-settle/src/hook.rs:247`).
- The settlement machinery this design reuses: amount-tiered dispute windows via
  `SettlementPolicyConfig::tier_for_amount`
  (`crates/economy/chio-settle/src/config.rs:118`, `:199`); watchdog jobs with
  `operator_override_required` retained
  (`crates/economy/chio-settle/src/automation.rs:61`, `:141`); emergency modes
  `Normal | DispatchPaused | RefundOnly | RecoveryOnly | Halted` gating lanes via
  `SettlementEmergencyControls::allows` (`crates/economy/chio-settle/src/ops.rs:43`,
  `:94`); and the EIP-3009, x402, and Circle rail primitives in
  `crates/economy/chio-settle/src/payments.rs` (`:15`, `:48`, `:317`, `:473`,
  `:681`).
- Kernel checkpoints Merkle-commit receipt batches and detect equivocation by
  conflicting sequence at the same position
  (`crates/kernel/chio-kernel/src/checkpoint.rs:92`, `:440`, `:785`). The
  commerce order log is the reference for a monotonic state ledger that rejects
  backwards and skipped transitions (`spec/PROTOCOL.md:1108`); per-receipt local
  signatures remain the authority, batch roots add continuity not authority
  (`spec/PROTOCOL.md:1238`).

## In scope

1. A pure contract crate `crates/economy/chio-channel` (`#![forbid(unsafe_code)]`,
   no I/O, serde types plus deterministic validation) defining the channel
   artifact family and its stale-state resolution.
2. Four signed artifacts under schema ids `chio.channel.<artifact>.v1`:
   `open`, `state`, `close`, `dispute`.
3. A post-persist channel-metering driver that composes at the existing
   receipt-persistence slot alongside the settlement observer, updating channel
   state from each allowed, positively priced receipt.
4. Off-chain channel accounting with rail net-settlement of the net at close
   (payment-adapter capture, EIP-3009 transfer-with-authorization, or Circle
   nanopayment evaluation).
5. Contested close over the existing tiered dispute-window and watchdog
   machinery, with latest-sequence-wins and fail-closed refund of the unspent
   bound per ADR-0015.
6. Ladder registration of the `channel_close` action class as a
   settlement-commitment (n-of-m quorum-required) per `spec/CHIO_LADDER.md` 5.2.

## Out of scope (explicit cuts)

- New Solidity. Any on-chain channel primitive is a family-v2 proposal gated on
  the external-assurance checklist (see the reality-check subsection below).
- Mainnet or public-testnet deployment, custody, or promotion (invariant 6).
- Mutable bounds or channel top-up. A larger ceiling is a new channel; the bound
  is immutable once opened.
- Multi-currency channels. A channel is single-currency; a receipt in another
  currency is not meterable into it and settles per-call.
- Cross-issuer or multilateral netting. That is WS4 (Clearinghouse); a channel
  is strictly bilateral.

## Design

### Channel state machine

Lifecycle states advance monotonically, modeled on the commerce order log
(`spec/PROTOCOL.md:1108`): `Open` -> `Active` -> `ClosePending` -> `Closed`.
Backwards transitions and skipped states are rejections.

- `Open`: both parties have signed `chio.channel.open.v1` binding a funding
  reference and a hard bound; no value metered yet.
- `Active`: two monotone quantities advance one metered receipt at a time, a
  strictly increasing `seq` (u64) and a non-decreasing `cumulative_owed`
  (`MonetaryAmount`) that never exceeds the bound. Money math is integer minor
  units, checked, and fails closed rather than wrapping (invariant 2).
- `ClosePending`: a close is posted and a tiered dispute window runs, during
  which a strictly-higher-`seq` mutually-signed state supersedes.
- `Closed`: the final state settles; the net releases to the payee and the
  remainder is accounted to the payer.

The latest mutually-signed state wins. Presenting a stale (lower-`seq`) state to
underpay or a fabricated high state to overclaim is the classic channel attack;
it is resolved by the dispute window plus latest-sequence-wins, which is the
same conflicting-sequence discipline the checkpoint layer already encodes
(`crates/kernel/chio-kernel/src/checkpoint.rs:440`).

### Artifacts and types (schema ids `chio.channel.<artifact>.v1`)

All artifacts are canonical JSON (RFC 8785), signed, with schema-id constants,
JSON schemas under `spec/schemas/`, and conformance coverage (invariant 5).

- `chio.channel.open.v1`: `channel_id` (deterministic hash of terms),
  `payer` and `payee` party bindings, `funding_reference` (a typed enum: escrow
  deposit reference, x402 prepayment reference, or EIP-3009 authorization
  digest), `bound` (`MonetaryAmount`), `expiry` (unix seconds),
  `dispute_window_class` (the `SettlementAmountTier` selected for the bound), and
  both open signatures.
- `chio.channel.state.v1`: `channel_id`, `seq`, `cumulative_owed`,
  `metered_receipts_root` (Merkle root over the ordered metered receipt ids),
  `metered_count`, `payer_signature`, and an optional `payee_countersignature`.
  A state is "mutually-signed" only when both signatures are present.
- `chio.channel.close.v1`: `channel_id`, `close_kind` (`cooperative | contested`),
  `final_seq`, `final_cumulative_owed`, `refund_remainder`
  (`bound - final_cumulative_owed`, integer), a settlement reference, and the
  signatures required by the close kind.
- `chio.channel.dispute.v1`: a challenge that carries a strictly-higher-`seq`
  mutually-signed `chio.channel.state.v1` to supersede a posted close.

The channel state is evidence-referential: `metered_receipts_root` binds the
channel to real receipt ids that each trace to an independently signed receipt.
The state asserts no authority of its own (invariant 1; `spec/PROTOCOL.md:1238`).

### Data flow

1. Open. Payer and payee agree terms and bind a funding reference for `bound`.
   Both sign `chio.channel.open.v1`.
2. Meter. Each allowed receipt with positive `cost_charged` drives the channel:
   the post-persist driver reads `cost_charged` and `currency`
   (`crates/kernel/chio-kernel/src/kernel/settlement_observer.rs:92`), appends
   the receipt id to the metered set, recomputes `metered_receipts_root`,
   increments `seq`, and adds the cost to `cumulative_owed` under a checked bound
   check, emitting a payer-signed `chio.channel.state.v1` that the payee
   countersigns on receipt of value. The driver never gates the call: budget
   enforcement (`ChioKernel::check_and_increment_budget`,
   `docs/reference/AGENT_ECONOMY.md:120`) already bound it upstream, and the
   driver runs downstream of the already-signed receipt.
3. Close. Cooperative or contested (below). The net settles once over the rail.

### Close and dispute handling

Cooperative close. Both parties sign `chio.channel.close.v1` over the final
mutually-signed state. The net (`final_cumulative_owed`) is captured to the payee
over the rail: a payment-adapter capture, an EIP-3009
`transfer_with_authorization` minted for exactly the net at close, or a Circle
nanopayment evaluation (`crates/economy/chio-settle/src/payments.rs:473`, `:681`).
The remainder is never captured (a rail authorization for only the net simply
leaves the rest unused).

Contested close. A party posts a `chio.channel.close.v1` citing the best state it
holds, which moves the channel to `ClosePending` and opens the dispute window
sized by `SettlementPolicyConfig::tier_for_amount(cumulative)`
(`crates/economy/chio-settle/src/config.rs:199`). A watchdog job monitors the
window (`build_settlement_watchdog_job`, `assess_watchdog_execution`,
`crates/economy/chio-settle/src/automation.rs:61`) with operator override
retained. During the window, any `chio.channel.dispute.v1` carrying a
strictly-higher-`seq` mutually-signed state supersedes the posted state. At
window expiry with no superseding state, the posted state is final.

Predeclared, price-free outcomes (ADR-0015 D2, D4;
`docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md:59`, `:87`). A close
yields exactly two amounts: release-to-payee of `cumulative_owed` and
refund-of-remainder to payer of `bound - cumulative_owed`. Both are proven by
signed states, never quoted; `cumulative_owed` is monotone and only shrinks
relative to the bound; the protocol is never the payee. The contested path
chooses among fixed states (which mutually-signed state is latest), it never
invents an amount (the D5 analog). The stale-state attack fails structurally: a
payee beats a stale low state by presenting the latest mutually-signed higher
state that the payer also signed, and a payee cannot fabricate a high state
because every state requires the payer signature and is Merkle-bound to real
receipt ids.

Counterparty-recovery strength depends on the funding reference and is stated
plainly. An escrow deposit or an x402 `EscrowBacked` prepayment pre-commits
custody of the bound, so a contested close can claim `cumulative_owed` against
it. A bare EIP-3009 authorization pre-commits no custody: cooperative close mints
the net authorization, but a non-cooperative payer can withhold it, reducing the
payee's guarantee to "the bound was never exceeded and the mutually-signed
evidence is dispositive," not on-chain recovery. The channel bounds exposure to
`bound` in every case; it never manufactures custody the funding reference does
not provide.

### On-chain settlement reality check and family-v2 boundary

Verified in source, loudly, because the design hinges on it:

- `ChioEscrow` DOES express partial-amount release.
  `partialReleaseWithProofDetailed` (`contracts/src/ChioEscrow.sol:240`;
  declared in `contracts/src/interfaces/IChioEscrow.sol:110`) releases an
  arbitrary `amount` bounded by `_ensureReleaseAmount`
  (`escrow.released + amount <= escrow.deposited`,
  `contracts/src/ChioEscrow.sol:361`), increments `escrow.released`
  (`:458`), and emits `EscrowPartialRelease` (`:461`). ADR-0015 D2 already
  blesses it as a compliant terminal outcome
  (`docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md:176`). The brief's
  hypothesis that the contract cannot express partial release is therefore false
  at the contract level.
- Two gaps nonetheless keep on-chain channel close out of shipped scope. First,
  there is no atomic dual-payout. Release-to-payee
  (`partialReleaseWithProofDetailed`) and refund-to-payer (`refund`,
  `contracts/src/ChioEscrow.sol:268`) are separate transactions, and `refund`
  is gated on `block.timestamp > escrow.terms.deadline` (`:271`). An
  escrow-funded channel would thus close as: payee partial-claims the cumulative
  during the window (with escrow `deadline` set to expiry plus dispute window);
  the remainder returns to the payer only after that deadline. Correct and
  ADR-0015-compliant, but non-atomic and deadline-delayed. Second, the Rust
  settlement runtime does not expose partial release at all: it ships
  `prepare_merkle_release` (full-drain, `crates/economy/chio-settle/src/evm/prepare.rs:248`),
  `prepare_dual_sign_release`, and `prepare_escrow_refund` (`:1182`) only.

Family-v2 proposal (deferred, gated on external assurance). A first-class
on-chain channel primitive that commits a monotonic sequence and stale-state
challenge on chain and performs an atomic net close (release cumulative to payee,
return remainder to payer in one transaction, no deadline wait). Any such
primitive MUST preserve ADR-0015 D1/D2/D4: no admin, pause, or upgrade lane;
exactly the two predeclared price-free outcomes; the protocol never a payee;
amounts evidenced and monotone. This is new Solidity, out of scope for the
shipped wave (program design lines 73-75, 163-165; invariant 6). Wiring the
existing `partialReleaseWithProofDetailed` into the Rust runtime is additive Rust
but stays devnet-only under the freeze.

### Integration points

- Post-persist channel driver. Composes at
  `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:185`,
  the same site the settlement observer runs, wired through `chio-control-plane`
  rather than kernel business logic (invariant 4). It shares the observer
  contract: observer-only relative to receipt bytes, never blocks dispatch, fails
  open (a metering failure routes to retry and the receipt falls back to per-call
  settlement; the receipt is already committed). Metering is evidence production,
  not a gated settlement operation.
- Reuse without change: `chio-settle::payments` (EIP-3009, x402, Circle) for
  funding and net capture; `SettlementAmountTier` / `tier_for_amount` and the
  automation watchdogs for dispute windows; and `platform/chio-store-sqlite`
  traits for persistence (invariant 4).
- Emergency modes: a channel close maps to the `ReleaseEscrow` and `RefundEscrow`
  operation kinds (`crates/economy/chio-settle/src/ops.rs:53`). Under `RefundOnly`
  the release leg is paused while contested-close-to-refund proceeds (fail-closed
  toward the payer); under `Halted` no channel operation proceeds.

### Error handling (fail-closed)

- Cumulative would exceed bound: the state is rejected, the channel is full, and
  subsequent calls settle per-call. The bound is never raised in place.
- Sequence regression, missing countersignature, currency drift,
  `metered_receipts_root` mismatch, or an unbound receipt id: the state is
  rejected and the last mutually-signed state stands.
- Any unverifiable state at close: contested close at the last mutually-signed
  state.
- No mutually-signed state exists at close: refund the entire bound to the payer
  (cumulative is zero).
- Mixed currency: null total (invariant 3); the offending receipt is not
  meterable and settles per-call.

## Alternatives considered

1. Extend `ChioEscrow` now with a native channel-close primitive (on-chain
   sequence, stale-state challenge, atomic dual-payout). Rejected: new Solidity
   under the freeze (invariant 6; ADR-0015 D1 forbids acquiring new privileged
   lanes without predeclaration). It belongs in a family-v2 proposal gated on
   external assurance.
2. Extend `allow_then_settle` with pure off-chain accumulation and no ceiling.
   Rejected: unbounded counterparty exposure is exactly the problem WS5 exists to
   solve; the bound is the point.
3. Per-call micro-settlement over Circle nanopayments
   (`crates/economy/chio-settle/src/payments.rs:681`). Rejected: still one rail
   action per call, so fees and latency defeat the high-frequency case; channels
   net N calls into one settlement.

Recommendation: off-chain receipt-metered channels with a hard bound and rail
net-settlement, with escrow-funded on-chain close deferred to a family-v2
proposal. This fits the freeze, reuses WS1 and the settlement machinery, and
closes the exposure gap without new custody claims.

## Claim and release framing

- Claim track: implementation (program design line 147). WS5 is engineering
  within the bounded release posture.
- Channels are signed intent plus reconciliation evidence, not custody and not
  finality (invariant 7). No distributed-linearizable spend truth is asserted;
  the HA overrun bound (ADR-0006) stands, and channel states are subordinate to
  per-receipt authority (`spec/PROTOCOL.md:1238`).
- No mainnet or public-testnet (invariant 6). Shipped scope is off-chain
  accounting plus rail net-settlement plus devnet qualification. On-chain
  escrow-funded close is a family-v2 proposal.
- Ladder anchoring (invariant 8): `channel_close` is a settlement commitment and
  stays n-of-m quorum-required per `spec/CHIO_LADDER.md` 5.2; metering is
  evidence production, not a settlement commitment. The action class is added to
  the ladder in this phase.
- No repricing, monotone amounts, protocol never the payee (ADR-0015 D2, D4).

## Testing strategy

- Deterministic validation in `chio-channel`: sequence monotonicity, cumulative
  bound check, `metered_receipts_root` recomputation, single-currency
  enforcement, and signature and countersignature checks; plus conformance
  coverage for each `chio.channel.<artifact>.v1` schema (invariant 5).
- Stale-state proptest over the product of sequence order, which party posts the
  close, and presence of a superseding state: latest mutually-signed wins and
  fabricated states are rejected.
- Fail-closed tests: unverifiable state resolves to contested close at the last
  mutually-signed state; absence of any mutually-signed state refunds the full
  bound; cumulative-exceeds-bound is rejected.
- ADR-0015 property test: no close outcome pays the protocol; release-cumulative
  plus refund-remainder equals the bound; amounts are monotone.
- Dispute-window watchdog test reusing `assess_watchdog_execution`
  (`crates/economy/chio-settle/src/automation.rs:141`), and a rail net-settlement
  test exercising EIP-3009 nonce replay protection for the net capture
  (`crates/economy/chio-settle/src/payments.rs:317`).
- Integration test against a real kernel mirroring the settlement-observer
  invariant that receipts are byte-identical whether or not the driver is wired
  (`crates/kernel/chio-kernel/src/kernel/settlement_observer.rs:11`): metering
  never mutates receipt bytes and never blocks dispatch.

## Implementation phases

- M1 (chio-channel contract crate). Artifacts, schema-id constants, deterministic
  validation, stale-state resolution, and the ADR-0015 outcome check. Offline, no
  kernel wiring; lands independently of WS1 in the economy-crate pattern.
- M2 (metering driver and rail net-settlement). Wire the post-persist driver
  through `chio-control-plane`; net capture over the payment adapter, EIP-3009,
  x402, or Circle; dispute-window and watchdog integration; emergency-mode
  classification. Depends on WS1 settlement wiring.
- M3 (devnet escrow-funded close, optional). Escrow deposit as funding reference
  with post-deadline refund of remainder; wire `partialReleaseWithProofDetailed`
  into the Rust runtime if pursued; devnet qualification only. Anything needing
  new Solidity stops at the family-v2 boundary.

## Open questions

1. ChioEscrow partial-release verdict (resolved; see the reality-check
   subsection): the contract supports partial release, the Rust runtime does not
   expose it, and there is no atomic dual-payout, so on-chain channel close is a
   family-v2 proposal, not shipped scope.
2. Operation-kind granularity: add a `SettlementOperationKind::CloseChannel`, or
   keep mapping the close legs onto `ReleaseEscrow` and `RefundEscrow`
   (`crates/economy/chio-settle/src/ops.rs:53`)?
3. Countersignature liveness: the "mutually-signed" requirement assumes a
   responsive payee. What is the fallback for an un-countersigned tail beyond
   per-call settlement of those receipts?
4. Merkle leaf domain: bind receipt ids directly, or reuse the kernel checkpoint
   leaf domain of canonical receipt bytes and `ReceiptInclusionProof`
   (`crates/kernel/chio-kernel/src/checkpoint.rs:92`, `:785`) so channel and
   checkpoint evidence share a proof format?
5. Channel scoping: `SettlementObservation` carries an optional `tenant_id`
   (`crates/economy/chio-settle/src/hook.rs:53`); is a channel keyed by
   (payer, payee, tenant, currency)?
