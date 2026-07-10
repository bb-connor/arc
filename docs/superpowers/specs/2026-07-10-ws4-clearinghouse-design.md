# WS4 Design: Chio Clearinghouse (multilateral netting)

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: WS1 for dispatch of netted settlement; netting engine and artifacts land independently
- Claim track: implementation (netting output is signed intent and evidence, never settlement truth)
- Branch: chio/ws4-clearinghouse off main

## Goal

Turn N counterparties' signed economic-position evidence into a deterministic,
reproducible set of netted pairwise obligations for a settlement epoch, so that
one settlement packet per counterparty pair replaces many per-call settlements.
The netting output is signed intent plus reconciliation evidence: never custody,
never finality, never a clearing or settlement rail. Any verifier holding the
same inputs recomputes byte-identical outputs.

## Context

`docs/reference/AGENT_ECONOMY.md:1267` scopes "Cross-Org Settlement" as a later
phase: a "Batch settlement engine walking delegation chains" with "Net position
calculation per organization" and "Multi-currency support and exchange rate
snapshotting" (lines 1269-1273). WS4 pulls that engine forward as a pure
deterministic function over already-signed evidence, without touching the
contract-freeze posture.

The inputs already exist as signed artifacts. `EXPOSURE_LEDGER_SCHEMA`
(`chio.credit.exposure-ledger.v1`, `crates/economy/chio-credit/src/lib.rs:62`)
carries `ExposureLedgerReport` (`lib.rs:332`), signed as `SignedExposureLedgerReport`
(`lib.rs:345`). It is subject-scoped and partitions positions by currency
(`ExposureLedgerCurrencyPosition`, `lib.rs:244`) rather than netting across them
(`AGENT_ECONOMY.md:893`). Its embedded `receipts` entries (`ExposureLedgerReceiptEntry`,
`lib.rs:259`) carry the directional atoms this design needs: `subject_key`,
`issuer_key`, `tool_server`, `settlement_status`, `financial_amount`.
`IouEnvelopeBody` (`crates/economy/chio-credit/src/hook.rs:57`, schema
`chio.credit.iou-envelope.v1` at `hook.rs:22`) is an explicit debt atom:
`tenant_id` owes (`hook.rs:71`), `issuer_key` is owed (`hook.rs:87`),
`amount_units` and `currency` (`hook.rs:82`). `SettlementStatus`
(`crates/core/chio-core-types/src/receipt/economics.rs:115`) distinguishes
`Pending`, `Settled`, `Failed`, `NotApplicable`.

Cross-currency precedent is uniformly fail-closed:
`ExposureLedgerSupportBoundary.cross_currency_netting_supported` defaults false
(`lib.rs:226`, `lib.rs:237`); `CapitalBookSupportBoundary.mixed_currency_netting_supported`
defaults false (`crates/economy/chio-credit/src/credit/capital_and_execution/capital_book.rs:56`,
`:65`); billing export nulls its total on mixed currency
(`crates/economy/chio-metering/src/export.rs:127`, test at `:236`). Permitted
conversion uses signed integer-rational evidence: `OracleConversionEvidence`
(`crates/core/chio-core-types/src/oracle.rs:9`, schema at `:7`) with
`rate_numerator` / `rate_denominator` as `u64` (`oracle.rs:16`), produced from
`ExchangeRate` (`crates/economy/chio-link/src/lib.rs:60`) via `to_conversion_evidence`
(`lib.rs:150`) after `ensure_fresh` (`lib.rs:104`).

Downstream, `SettlementCommitment` (`crates/economy/chio-settle/src/lib.rs:93`)
lives in a `#![cfg(feature = "web3")]` runtime crate (`lib.rs:9`), dispatches via
`prepare_merkle_release` (`chio-settle/src/evm/prepare.rs:248`), and reconciles
through `SettlementOutcome` (`chio-settle/src/lib.rs:54`). The commerce packet
`chio.commerce.settlement-packet.v1` (`spec/PROTOCOL.md:1120`) binds "settlement
dispatch, reconciliation, destination, amount, currency, and external settlement
references" and fails closed on "settlement packet mismatch, duplicate completion"
(`PROTOCOL.md:1126`). The ladder class `settle.commitment` is quorum-required
(`spec/CHIO_LADDER.md:707`: `co_sign: n_of_m`, `{n:2,m:3}`, `consistency_anchor:
frost-quorum`). Control-plane report and mutate endpoints build from the receipt
store, sign with `SignedExportEnvelope::sign`, and register a path
(`crates/platform/chio-control-plane/src/trust_control/credit_and_loss.rs:39`,
`service_runtime/router.rs:317`). Money is `MonetaryAmount` (`chio-credit/src/lib.rs:52`).

## In scope

1. A new pure crate `crates/economy/chio-clearing` (`#![forbid(unsafe_code)]`, no
   I/O) that computes a netting round from signed inputs and emits signed artifacts.
2. A deterministic engine: bilateral netting per currency, then multilateral cycle
   cancellation, integer math only, canonical ordering, reproducible byte-for-byte.
3. Four artifact families under `chio.clearing.<artifact>.v1`: netting round,
   net-position statement, clearing settlement packet, round dispute.
4. Per-currency netting by default; evidence-gated cross-currency netting only when
   a signed `OracleConversionEvidence` covers every conversion used.
5. Control-plane round orchestration (propose, report, dispute) following the
   trust-control report/mutate pattern, plus a `chio-store-sqlite` persistence trait.
6. A new ladder action class `clearing.round_finalize` with a declared dispute
   window; finalization is quorum-gated and fail-closed on dispute.
7. Reconciliation binding: WS1 settlement outcomes bind back to packets; unsettled
   or failed net positions reopen into the next round.

## Out of scope (explicit cuts)

- Fund movement, custody, and on-chain dispatch. Packets are intent; WS1 and the
  quorum-gated `settle.commitment` surface execute them. No new Solidity or contract
  surface (program invariant 6); the freeze is untouched.
- Any inter-organization clearing network, message bus, or live-state consensus.
  WS4 nets a fixed set of locally submitted signed inputs; it is not the
  "cross-network clearing" that `AGENT_ECONOMY.md:1015` and `:1028` disclaim.
- Live price fetching. The oracle runtime (`chio-link`) is not a dependency; only
  the already-signed `OracleConversionEvidence` type is consumed.
- The canonical participant-identity registry (organization to key set). WS4 binds
  a signed participant set into each round and defers the registry to WS6.
- Rewriting exposure-ledger or IOU schemas. WS4 reads them unchanged.

## Design

### Netting algorithm (deterministic)

`compute_netting_round(input) -> NettingRoundArtifact` takes a `round_id`, `epoch`,
`algorithm_version`, a canonical participant set, per-participant
`SignedExposureLedgerReport`s and signed `IouEnvelope`s, and optional signed
`OracleConversionEvidence`.

1. Verify and bind. Every envelope is checked (`SignedExportEnvelope::verify_signature`
   at `lineage.rs:431`, `IouEnvelope::verify_signature` at `hook.rs:108`). Any
   failure rejects the whole round. Each accepted input is hashed over its canonical
   JSON (RFC 8785) into the input manifest.
2. Extract obligation atoms per currency. From exposure-ledger receipt entries with
   `settlement_status == Pending` and a `financial_amount`: debtor owns `subject_key`,
   creditor owns `issuer_key` (or the `tool_server` provider), amount is
   `financial_amount`. From IOU envelopes: debtor is `tenant_id`, creditor is
   `issuer_key`, amount is `amount_units`. `Settled` and `NotApplicable` are excluded;
   `Failed` routes to reconciliation, not netting. An atom whose debtor or creditor
   does not resolve to a declared participant rejects the round (no silent drop).
3. Bilateral netting. Order each pair canonically (`party_a < party_b` by id bytes).
   Per currency, `gross_out` sums `a -> b` atoms and `gross_in` sums `b -> a`, both
   with `saturating_add` over atoms in canonical (currency, debtor, creditor,
   source-digest) order. The net is `net_debtor = party_a if gross_out >= gross_in
   else party_b` and `net_amount = larger.saturating_sub(smaller)`, so it never wraps
   and the sign rides the debtor field.
4. Multilateral cancellation. Per currency, treat post-bilateral obligations as
   directed edges (`debtor -> creditor`, weight). Repeat: starting from participants
   in canonical order and exploring out-edges in canonical creditor order, take the
   first simple cycle; let `m` be its minimum edge weight; subtract `m` (saturating)
   from every edge and drop zeroed edges. Each pass zeroes at least one edge, so the
   loop terminates; canonical start and neighbor order fix the sequence. Residual
   edges are the settlement obligations.
5. Emit. One `NetPositionStatement` per pair per currency (`gross_out`, `gross_in`,
   `bilateral_net`, `multilateral_adjustment`, residual `net_settlement_amount`).
   One `ClearingSettlementPacket` per pair per epoch for each residual above zero.

A per-currency conservation invariant holds: the sum of net-debtor amounts equals
the sum of net-creditor amounts. Determinism rests on canonical participant and atom
ordering, saturating integer math (never wrapping), per-currency isolation, and
RFC 8785 output.

### Artifacts and types (schema ids chio.clearing.<artifact>.v1)

- `chio.clearing.netting-round.v1` (`NettingRoundArtifact`): `round_id`, `epoch`,
  `algorithm_version`, `generated_at`, canonical `participants`, a
  `ClearingSupportBoundary` (mirroring the exposure-ledger boundary, with
  `cross_currency_netting_supported` defaulting false), an `input_manifest`
  (per input: participant, artifact kind, schema, canonical digest, signer key),
  an `output_manifest` (statement and packet digests), and a per-currency summary
  (atom count, gross total, netted total, cycles cancelled, `arithmetic_saturated`).
  Signed as `SignedNettingRound = SignedExportEnvelope<NettingRoundArtifact>`.
- `chio.clearing.net-position-statement.v1` (`NetPositionStatement`): `round_id`,
  `epoch`, `currency`, canonical `party_a` / `party_b`, `gross_out`, `gross_in`,
  `bilateral_net`, `multilateral_adjustment`, `net_settlement_amount` (`MonetaryAmount`),
  `net_debtor`, `net_creditor`, contributing input digests, `dispute_window`. Signed
  individually so a pair can present only its own statement.
- `chio.clearing.settlement-packet.v1` (`ClearingSettlementPacket`): a
  settlement-packet-family member consistent with `PROTOCOL.md:1120`. Binds
  `packet_id`, `round_id`, `epoch`, `net_debtor`, `net_creditor`, `destination`,
  `amount` (`MonetaryAmount`), `currency`, source statement digest, `reconciliation`
  (unbound until settled), `external_settlement_references` (empty until WS1
  dispatch). It is intent for a `settle.commitment`, not a `SettlementCommitment`
  (`chio-settle/src/lib.rs:93`) itself.
- `chio.clearing.round-dispute.v1` (`RoundDispute`): `round_id`, disputing
  participant, disputed statement digests, reason code, evidence references. A valid
  in-window dispute blocks finalization.

All four are canonical-JSON serde types with `deny_unknown_fields`, versioned schema
constants, and JSON schemas under `spec/schemas/` (program invariant 5).

### Data flow

The control plane gathers per-participant `SignedExposureLedgerReport`s (built via
the existing exposure-ledger endpoint, `credit_and_loss.rs:39`), IOU envelopes, and
optional conversion evidence for one epoch, runs `compute_netting_round` pure in
`chio-clearing`, then signs the round, statements, and packets and persists them
behind a `chio-store-sqlite` trait. The round publishes in a proposed state, opening
the dispute window. After the window closes with no valid dispute and an assembled
`clearing.round_finalize` quorum, the round finalizes and its packets become
dispatchable. WS1 settlement outcomes (`SettlementOutcome`, `chio-settle/src/lib.rs:54`)
bind to each packet; unsettled or failed net positions reopen as carried-forward atoms
in the next round's inputs.

### Integration points

- chio-credit (types only): consumes `ExposureLedgerReport` /
  `SignedExposureLedgerReport` and `IouEnvelope`. New dependency
  `chio-clearing -> chio-credit`.
- chio-core-types: `MonetaryAmount`, `OracleConversionEvidence`, `SignedExportEnvelope`,
  `SettlementStatus`. No dependency on `chio-link` or `chio-settle` (both
  web3-feature-gated), keeping `chio-clearing` pure.
- chio-control-plane: new endpoints follow `service_runtime/router.rs:317` (GET round
  report, POST propose, POST dispute, POST finalize) using the `credit_and_loss.rs`
  build-then-sign pattern with `TrustHttpError`.
- WS1 / chio-settle: packets feed `settle.commitment` dispatch; reconciliation returns
  via `SettlementOutcome`. The coupling is the packet schema plus WS1 wiring, never a
  direct crate dependency.
- spec: register `chio.clearing.settlement-packet.v1` in the `PROTOCOL.md:1098`
  settlement-packet family, and add `clearing.round_finalize` to `CHIO_LADDER.md:602` in
  the same phase (program invariant 8). It mirrors `settle.commitment` (`CHIO_LADDER.md:707`):
  `mode: receipt_backed`, `destructive: true`, `co_sign: n_of_m`, `co_sign_quorum: {n:2,
  m:3, scope: treaty}`, `consistency_model: quorum-required`, `consistency_anchor:
  frost-quorum`. Proposing a round and filing a dispute are non-destructive; only
  finalization, which unlocks dispatch, is destructive and quorum-gated.

### Error handling (fail-closed)

- The whole round rejects on any invalid input signature or any obligation atom with
  an unresolved debtor or creditor (no silent drop).
- Mixed currency without full conversion evidence nets each currency separately with no
  cross-currency total (mirrors `export.rs:127`); conversion evidence that is unsigned,
  stale, or future-dated is refused, falling back to separate netting rather than
  coercing a rate.
- A saturating sum sets `arithmetic_saturated` and blocks finalization rather than
  emitting a wrong net.
- If a participant's derived pairwise obligations exceed its own signed exposure-ledger
  currency position, the round rejects: a participant's signed truth bounds its obligations.
- A valid in-window dispute, or an unassembled quorum, blocks finalization; packets stay
  non-dispatchable.
- Failed or absent settlement reopens the net position into the next round; it is never
  silently dropped.

## Alternatives considered

1. Crate placement: new pure `chio-clearing` (recommended), extend `chio-credit`, or
   extend `chio-settle`. `chio-settle` is `#![cfg(feature = "web3")]` (`lib.rs:9`), so
   it cannot host an always-compiled pure artifact family, and settlement execution is
   downstream of netting. `chio-credit` is subject-scoped credit, IOU, and capital
   (already a 924-line `lib.rs`); multilateral cross-counterparty netting is a distinct
   concern that would overload it. Recommendation: a new pure `crates/economy/chio-clearing`,
   independently testable and matching program invariant 4.
2. Netting granularity: bilateral only, bilateral plus multilateral cycle cancellation
   (recommended), or full collapse to one net per participant. Cancellation minimizes
   settlement count and amount while preserving the per-pair statements the settlement
   packets and per-pair disputes require; collapsing to one net per participant loses
   the who-owes-whom those need. Recommendation: bilateral then multilateral cancellation.
3. Cross-currency: reject any mixed-currency round, per-currency by default with
   evidence-gated conversion (recommended), or always convert to a base currency.
   Per-currency-default matches every precedent (`lib.rs:226`, `capital_book.rs:56`,
   `export.rs:127`) and fails closed; always-convert would fabricate cross-rate risk
   into settlement intent. Recommendation: per-currency by default, cross-currency only
   under attached signed `OracleConversionEvidence`.

## Claim and release framing

Claim track: implementation (program design lines 147-150). Netting output is signed,
evidence-referential intent plus reconciliation evidence: not custody, not finality, not
an insurer-of-record, not a rail. "Clearinghouse" names the deterministic netting
function, not a custodial clearing counterparty, and is explicitly distinct from the
"cross-network clearing" that `AGENT_ECONOMY.md:1015` disclaims. Per program invariant 7,
no round asserts distributed-linearizable truth: a round is a pure function over a fixed
input set, reproducible by any verifier, not a consensus over live state. Settlement
packets ride the existing quorum-gated surface (invariant 8); any new on-chain need is a
family-v2 proposal, out of scope (invariant 6). A Pending obligation never becomes a
settled fact until WS1 reconciliation binds an outcome to its packet.

## Testing strategy

- Reproducibility: property test shuffling input, participant, and atom order, asserting
  byte-identical canonical-JSON artifacts; golden multi-participant, multi-currency
  vectors snapshotted with `insta` using `sort_maps` for cross-environment stability.
- Correctness: per-currency conservation (net debtors equal net creditors); a k-cycle
  cancels to zero; a chain reduces to its endpoints.
- Fail-closed: invalid signature, unresolved atom, stale or absent conversion evidence,
  arithmetic saturation, and obligations exceeding a signed position each reject or
  degrade as specified.
- Lifecycle: an in-window dispute or unassembled quorum blocks finalize; an out-of-window
  dispute is ignored; a failed settlement reopens its position into the next round while a
  settled packet does not.
- Conformance: schema registration for the four families; settlement-packet-family
  membership against `PROTOCOL.md:1098`; `clearing.round_finalize` passing ladder
  validation (`n_of_m` requires `co_sign_quorum`, `quorum-required` requires
  `consistency_anchor`, `CHIO_LADDER.md:281`). The workspace gate (build, test, clippy
  `-D warnings`, fmt) passes.

## Implementation phases

- Phase 1 (artifacts and engine, independent of WS1): the `chio-clearing` crate, the
  four schema families with constants and JSON schemas, `compute_netting_round`, and the
  property, golden, conservation, and fail-closed tests. No I/O, no wiring. Lands
  independently, per the wave-2 rule that artifact crates precede production money wiring.
- Phase 2 (persistence and control plane): the `chio-store-sqlite` trait, the propose,
  report, and dispute endpoints, artifact signing, and the dispute-window state machine.
  Still no money movement.
- Phase 3 (ladder, finalize, reconciliation): add `clearing.round_finalize` to
  `CHIO_LADDER.md:602`, the quorum-gated finalize path, the `PROTOCOL.md:1098`
  settlement-packet reconciliation, packet binding to WS1 `settle.commitment` dispatch
  and `SettlementOutcome`, and the reopen-unsettled logic. Gated on WS1 for dispatch.

## Open questions

1. Participant identity. Exposure ledgers key on `subject_key` / `capability_id` /
   `tool_server`, IOUs on `tenant_id` / `issuer_key`, settlement on `operator_identity`
   (`chio-settle/src/lib.rs:100`). WS4 binds a signed participant set into each round and
   defers the durable organization-to-key registry to WS6. Where is the authoritative
   mapping owned?
2. Protocol family placement. Registering `chio.clearing.settlement-packet.v1` as a
   sibling of `chio.commerce.settlement-packet.v1` (`PROTOCOL.md:1120`) needs a normative
   edit; confirm it extends the commerce family versus a distinct clearing family reusing
   the same binding rules.
3. Dispute window and epoch cadence: operator-signed fiscal parameters (WS8) with a fixed
   fallback, or set by which authority?
4. Reopened positions. When a Failed or unsettled net position reopens, how is
   double-counting avoided against a still-Pending original that also reappears in the
   exposure ledger?
5. Obligation volume. `ExposureLedgerReceiptEntry` lists are bounded to 200
   (`MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT`, `lib.rs:83`). Deep histories may exceed that; does
   WS4 need a continuation or an explicit obligation-manifest artifact instead of embedded
   receipts?
6. Support-boundary reconciliation. The round should reuse `mixed_currency_netting_supported`
   (`capital_book.rs:56`) and `cross_currency_netting_supported` (`lib.rs:226`) semantics
   (default false, raised only with per-round conversion evidence). Confirm one shared flag
   name and that raising it is never a global capability.
