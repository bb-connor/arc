# WS3 Design: Verified-outcome pricing

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: WS1 for escrow-bound release execution; WS8 (soft) for penalty parameters
- Claim track: implementation
- Branch: chio/ws3-outcome-pricing off main

## Goal

Let a listing price a tool call on a machine-checkable outcome rather than on
an invocation or a metered unit. The kernel evaluates a declared predicate over
the tool output it actually observed, attests the verdict into the signed
receipt, and settles the charge against that verdict: full price when the
predicate passes, zero or a declared attempt-fee floor when it fails or cannot
be evaluated. The verdict is kernel-observed and receipt-signed; it never rests
on a tool-server self-report, and an unevaluable predicate is a failed outcome,
never a silent full charge.

## Context

Pricing today is per-invocation or per-metered-unit. A governed intent may
carry a `MeteredBillingContext` (`crates/core/chio-core-types/src/capability/governance.rs:93-103`)
whose `MeteredBillingQuote` (`.../governance.rs:65-90`) fixes a `billing_unit`
string, `quoted_units`, and a `quoted_cost` `MonetaryAmount`, under a
`MeteredSettlementMode` of `MustPrepay`, `HoldCapture`, or `AllowThenSettle`
(`.../governance.rs:53-62`). The quote is validated pre-execution by
`validate_metered_billing_context` (`crates/kernel/chio-kernel/src/kernel/governed_validation.rs:276-351`),
and PROTOCOL 5.2 (`spec/PROTOCOL.md:501-536`) frames the settlement mode as
evidence and operator context, not the hard enforcement boundary.

Post-execution reconciliation already exists. In
`finalize_budgeted_tool_output_with_cost_and_metadata`
(`crates/kernel/chio-kernel/src/kernel/validation.rs:927`), the kernel computes
an `actual_cost`, reconciles the hold (`validation.rs:1025`), and settles
through the `PaymentAdapter` (`crates/kernel/chio-kernel/src/payment.rs:150-181`):
`actual_cost == 0` calls `release`, otherwise `capture(actual_cost)`
(`validation.rs:1037-1046`); a reported cost above the hold is refused as a
`SettlementStatus::Failed` overrun (`validation.rs:1007-1017`;
`crates/core/chio-core-types/src/receipt/economics.rs:113-124`). This
release-or-capture fork is exactly the money movement WS3 needs, so it computes
a `reported_cost` from the verdict and lets the existing path settle it.

The guard substrate can inspect output. The post-invocation pipeline
(`crates/guards/chio-guards/src/post_invocation.rs`) runs `PostInvocationHook`s
returning `Allow`, `Block`, `Redact`, or `Escalate` and emits `GuardEvidence`
(`crates/core/chio-core-types/src/receipt/metadata.rs:182-190`) into the
receipt. A WASM guard runtime exists (`crates/guards/chio-wasm-guards/src/lib.rs`)
with a Component Model interface `chio:guard@0.1.0` and fail-closed fuel
metering, but its `GuardRequest` (`.../chio-wasm-guards/src/abi.rs:29`) is
input-shaped and its `GuardVerdict` is `Allow` or `Deny` (`abi.rs:62-66`).

Listings advertise price and SLA through an operator-signed `ListingPricingHint`
(`crates/economy/chio-listing/src/discovery.rs:48-109`, schema
`chio.marketplace.listing-pricing-hint.v1` at `discovery.rs:30`) carrying a
`price_per_call` `MonetaryAmount` and a `ListingSla` (`discovery.rs:116-135`).
SLA breach routes through governance-adjudicated open-market penalties:
`OpenMarketAbuseClass` (`crates/economy/chio-open-market/src/penalty.rs:19-26`)
drives an `OpenMarketPenaltyArtifact` (`penalty.rs:55-85`) requiring signed
charter, case, and fee schedule whose signers match trusted authority keys
(`crates/economy/chio-open-market/src/authority.rs:76-95`), backed by bonds in
`OpenMarketBondRequirement` (`crates/economy/chio-open-market/src/fee_schedule.rs:54-67`).
On-chain release binds to receipt bytes: `prepare_merkle_release`
(`crates/economy/chio-settle/src/evm/prepare.rs:248-296`) hashes the receipt
body into the escrow call, with `prepare_escrow_refund` (`prepare.rs:1182`) the
refund counterpart.

## In scope

1. A new pure contract crate `crates/economy/chio-outcome` defining the outcome
   predicate and outcome pricing artifacts, following the economy-crate pattern
   (`#![forbid(unsafe_code)]`, no I/O, serde types plus deterministic
   validation).
2. `chio.outcome.predicate.v1`: a declarative predicate over tool output with an
   extensible `form` vocabulary. Two forms ship in v1: a JSON-shape / JSONPath
   assertion, and a guard-verdict-class assertion (named output guards must
   pass). A `wasm_component` form is reserved and rejected at load in v1.
3. `chio.outcome.pricing.v1`: the outcome price (`MonetaryAmount`), the
   referenced predicate digest, and the failure mode (`ZeroCharge` or
   `AttemptFee { floor: MonetaryAmount }`). `ListingPricingHint` gains an
   optional digest reference to a signed pricing artifact.
4. `OutcomeVerdictReceiptMetadata` (schema `chio.outcome.verdict.v1`) in
   `crates/core/chio-core-types/src/receipt/`, carried as an optional field on
   `GovernedTransactionReceiptMetadata` alongside `metered_billing`.
5. An `OutcomeVerificationHook` kernel slot (a trait installed by control-plane
   wiring, mirroring the payment-adapter and price-oracle slots) that the
   budgeted finalize path consults to convert observed output plus verdict into
   a `reported_cost`, so the existing capture/release fork settles it unchanged.
6. Pre-execution validation extending `validate_metered_billing_context`: when a
   quote names a verified outcome, the referenced predicate and pricing
   artifacts must verify and be live, fail-closed.
7. `chio.outcome.sla-breach.v1`: an evidence artifact aggregating outcome-failed
   receipts against a declared SLA, consumable as an evidence reference in an
   `OpenMarketPenaltyIssueRequest`, plus an additive `OutcomeSlaBreach`
   abuse-class variant.
8. JSON schemas under `spec/schemas/chio-outcome/`, conformance coverage, and a
   PROTOCOL 5.2 reconciliation for the verified-outcome quote encoding.

## Out of scope

- New Solidity. Escrow release and refund reuse `prepare_merkle_release`,
  `prepare_dual_sign_release` (`prepare.rs:1027`), and `prepare_escrow_refund`
  unchanged; any new contract surface is a family-v2 proposal.
- A `wasm_component` predicate form and an output-carrying WASM guard ABI
  (deferred; see Alternatives).
- New receipt kinds. The verdict rides an existing `MediatedDecision` receipt
  (`crates/core/chio-core-types/src/receipt/kinds.rs:43-49`) as a metadata block.
- Subjective or model-judged outcomes. v1 predicates are deterministic over the
  observed output; panel adjudication of outcomes belongs to WS7.
- Production money movement ahead of WS1. The artifact family and its offline
  verification land independently; kernel settlement wiring is gated on WS1.

## Design

### Outcome predicates

A predicate is a signed `chio.outcome.predicate.v1` artifact with a `form`
discriminator so the vocabulary can grow without a schema break. v1 evaluates
two forms natively and deterministically:

- `json_assertion`: a list of JSONPath selectors with expected shape, presence,
  or comparison assertions over the tool output value. Passes when every
  assertion holds.
- `guard_verdict_class`: a set of named output guards that must return `Allow`
  from the post-invocation pipeline. This reuses `GuardEvidence` already
  produced for the receipt.

`wasm_component` is a reserved form value that rejects at load in v1.
Evaluation is total and side-effect free and produces `Passed`,
`Failed { reason }`, or `Unevaluable { reason }`, where `Unevaluable` covers
malformed output, a guard error, a missing or expired predicate, or an unknown
form. `Failed` and `Unevaluable` charge identically (the failure-mode floor) but
are recorded distinctly for audit.

The verdict authority is the kernel's own evaluation over the observed output
bytes, then the receipt signature. A tool may include a `"success": true` field,
but that is at most an input to a `json_assertion`, never the verdict, which
preserves the evidence-class discipline of PROTOCOL 5.2 (`spec/PROTOCOL.md:545-553`)
and 6.3.4 (`spec/PROTOCOL.md:1115`, subordinate evidence, not ambient authority).

### Artifacts and types (schema ids chio.outcome.<artifact>.v1)

- `chio.outcome.predicate.v1` (`chio-outcome`): `predicate_id`, `form`,
  form-specific body, `issued_at`, `expires_at`. Signed via
  `SignedExportEnvelope`.
- `chio.outcome.pricing.v1` (`chio-outcome`): `pricing_id`, `predicate_ref`
  (id plus sha256), `outcome_price: MonetaryAmount`, `failure_mode`
  (`ZeroCharge` or `AttemptFee { floor: MonetaryAmount }`), `issued_at`,
  `expires_at`. Validation requires `floor.currency == outcome_price.currency`
  and `floor.units <= outcome_price.units`.
- `OutcomeVerdictReceiptMetadata` (schema `chio.outcome.verdict.v1`,
  `crates/core/chio-core-types/src/receipt/`): `predicate_id`, `predicate_hash`,
  `form`, `verdict` (`passed` / `failed` / `unevaluable`), `evidence_class`
  reusing `GovernedProvenanceEvidenceClass` (`.../capability/governance.rs:472-482`,
  set to `observed`, never `verified` unless bound to further signed evidence),
  `charged_mode` (`outcome_price` / `zero` / `attempt_fee`), `charged_amount:
  MonetaryAmount`, and optional guard-evidence references. Added as an optional
  `outcome` field on `GovernedTransactionReceiptMetadata`
  (`.../receipt/governance.rs:101-139`), serialized under the existing
  `governed_transaction` metadata key
  (`crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs:433`).
- `chio.outcome.sla-breach.v1` (`chio-outcome`): `listing_id`, `predicate_ref`,
  declared SLA reference, an evidence set of outcome-failed receipt references,
  a breach window, and a computed failure ratio in basis points. It is evidence,
  not authority.

All monetary values are `MonetaryAmount`; ratios and margins are integer basis
points, consistent with `ListingSla` (`discovery.rs:116-135`). Artifacts are
canonical JSON with versioned schema-id constants.

### Data flow

1. Publish. The operator signs a `chio.outcome.predicate.v1` and a
   `chio.outcome.pricing.v1`, and references the pricing digest from the
   `ListingPricingHint`; buyers discover it through existing marketplace search.
2. Request. The buyer attaches `metered_billing` with a `HoldCapture` or
   `MustPrepay` mode, `quote.billing_unit = "verified_outcome"`,
   `quoted_units = 1`, `quoted_cost = outcome_price`, and the predicate and
   pricing references.
3. Pre-execution and hold. `validate_metered_billing_context` runs its existing
   checks and additionally verifies the referenced artifacts and their validity
   windows, fail-closed; the payment adapter `authorize`s the worst-case hold
   (the outcome price).
4. Execute the tool.
5. Verify. The budgeted finalize path invokes the `OutcomeVerificationHook` over
   the observed output, which returns a verdict and the resulting
   `reported_cost`: `outcome_price` on `Passed`; `0` or the attempt-fee floor on
   `Failed` / `Unevaluable`, per the declared failure mode.
6. Settle. The existing reconcile plus capture/release path
   (`validation.rs:1019-1046`) settles it: `reported_cost == 0` releases the
   hold, otherwise it captures the reported cost and the rail voids the
   remainder.
7. Attest. The receipt carries the `financial` block (`cost_charged` equals the
   settled amount) and the `governed_transaction.outcome`
   `OutcomeVerdictReceiptMetadata`.
8. Escrow (optional, WS1). A `Passed` receipt drives `prepare_merkle_release`,
   which binds the receipt bytes; a `Failed` receipt drives
   `prepare_escrow_refund`. A breach aggregator assembles
   `chio.outcome.sla-breach.v1` from failed receipts and submits it as evidence
   to an `OpenMarketPenaltyIssueRequest` under the unchanged authority path.

### Integration points

- Kernel: an `OutcomeVerificationHook` trait plus an optional kernel field and a
  control-plane installer, consulted inside
  `finalize_budgeted_tool_output_with_cost_and_metadata` (`validation.rs:927`)
  before `actual_cost` is computed. The kernel core stays thin; predicate logic
  lives in `chio-outcome` behind the trait, honoring the invariant that kernel
  integration goes through hook slots, not new kernel-side business logic. The
  guard-verdict-class form also needs the output guard pipeline to run in the
  budgeted path, which today runs only in the non-budgeted
  `finalize_tool_output_with_metadata`
  (`crates/kernel/chio-kernel/src/kernel/responses/finalization.rs:18-143`); see
  Open questions.
- Settlement: the post-dispatch settlement observer
  (`crates/kernel/chio-kernel/src/kernel/settlement_observer.rs:81-125`) already
  skips zero-priced receipts, so a released `Failed` outcome needs no special
  handling; a captured `Passed` or attempt-fee receipt flows to the WS1
  `SettlementHook` unchanged.
- Open market: the breach artifact enters through the existing evidence-ref
  field on `OpenMarketPenaltyIssueRequest` (`penalty.rs:132-181`); penalty
  issuance authority (`authority.rs:76-95`) and bond backing
  (`fee_schedule.rs:54-67`) are unchanged.

### Error handling (fail-closed)

- An unevaluable predicate is a failed outcome. The charge is the declared
  failure-mode floor (zero or attempt fee), never the outcome price, and never a
  silent full charge.
- A missing, expired, signature-invalid, or unknown-`form` predicate or pricing
  artifact denies pre-execution through `KernelError::GovernedTransactionDenied`,
  the same class `validate_metered_billing_context` already returns.
- If the `OutcomeVerificationHook` is absent while a verified-outcome quote is
  present, the request is denied rather than charged at face value.
- A reported cost above the hold remains the existing `SettlementStatus::Failed`
  overrun; the outcome path never widens the hold. Mixed-currency floor or price
  fails validation at load, matching the money invariant.

## Alternatives considered

1. Verdict authority: kernel-observed versus tool-server self-report. A tool
   returning `{"success": true}` that the kernel trusts would collapse the
   evidence classes and let a seller price its own success. Rejected. The kernel
   evaluates the predicate over the observed output and signs the verdict;
   self-report is at most a predicate input. Recommended.
2. Predicate form for v1: native declarative plus guard-verdict-class versus a
   WASM predicate component. The WASM runtime exists but its ABI is input-shaped
   (`abi.rs:29`), so an output predicate needs a new output-carrying request and
   a wider signed-module trust surface over priced outcomes. Recommended: ship
   `json_assertion` and `guard_verdict_class` natively, reserve `wasm_component`,
   keep the `form` enum open.
3. Charge integration: reuse capture/release via a computed `reported_cost`
   versus a bespoke outcome-settlement path that would fork the money path and
   undercut RFC-0013 durability. Recommended: reuse. `validation.rs:1037-1046`
   already maps zero to release and a positive cost to capture, so no new
   money-movement code and no new Solidity are required.

## Claim and release framing

WS3 is implementation within the bounded release posture. A `Passed` verdict
means the kernel-observed output satisfied a declared, machine-checkable
predicate; it does not assert the outcome is objectively correct or valuable.
The verdict evidence class is `observed`, never silently upgraded to `verified`,
and no custody, finality, or insurer-of-record claim attaches. The off-chain
capture/release path is the default; on-chain escrow binding stays devnet-only
under the contract freeze, and the breach artifact is evidence a
governance-adjudicated authority weighs, not an automatic slash.

## Testing strategy

- `chio-outcome` unit tests: predicate and pricing validation, unknown-form
  rejection, failure-mode currency and floor bounds, canonical-JSON stability,
  schema-id constants, and breach-ratio basis-point arithmetic with saturating
  `MonetaryAmount` math; plus conformance snapshots for `spec/schemas/chio-outcome/`.
- Kernel finalize tests: `Passed` captures the outcome price; `Failed` under
  `ZeroCharge` releases with `actual_cost == 0`; `Failed` under `AttemptFee`
  captures the floor; `Unevaluable` settles at the floor. Proptest over verdict
  times failure mode times settlement mode asserting the charge never exceeds
  the floor on a non-pass.
- Evidence-class test: a self-reported success field does not yield `Passed`
  unless the kernel predicate independently passes.
- Escrow selection (devnet): `Passed` routes to `prepare_merkle_release`,
  `Failed` to `prepare_escrow_refund`. Penalty path: a breach artifact is
  accepted as an evidence ref while issuance still requires the governance
  authority signers.
- Fail-closed tests: missing or expired predicate denies pre-execution; absent
  verification hook with a verified-outcome quote denies.

## Implementation phases

1. Offline family. Stand up `chio-outcome` with the predicate, pricing, and
   breach artifacts; add `OutcomeVerdictReceiptMetadata` to `chio-core-types`;
   native evaluator for both v1 forms; schemas and conformance. No kernel
   wiring. Lands independently of WS1.
2. Kernel verification hook. Add the `OutcomeVerificationHook` slot and thread
   it into the budgeted finalize path; extend
   `validate_metered_billing_context`; emit the receipt block; off-chain
   capture/release only. Gated on WS1 for production money movement.
3. Escrow binding and breach economics. Verdict-driven selection between
   `prepare_merkle_release` and `prepare_escrow_refund` (devnet); ship
   `chio.outcome.sla-breach.v1` and the `OutcomeSlaBreach` abuse class; wire
   breach evidence into the governance-adjudicated penalty path.

## Open questions

1. The budgeted finalize path does not run the post-invocation guard pipeline
   today (`validation.rs:1153-1179` builds the allow response directly). The
   `guard_verdict_class` form requires running output guards there. Confirm the
   cleanest way to share that evaluation with the non-budgeted path.
2. Predicate reference transport on the request: a typed field on
   `MeteredBillingContext` (a PROTOCOL 5.2 wire change) versus the untyped
   `governed_intent.context` value. A typed field is cleaner but wider.
3. `billing_unit` encoding: a reserved sentinel string `verified_outcome`
   (additive, matches the free-string treatment in `spec/METERING.md:52-61`)
   versus a structured billing-unit enum.
4. Abuse-class growth: an additive `OutcomeSlaBreach` variant versus reusing the
   existing `UnverifiableListingBehavior` (`penalty.rs:19-26`).
5. Brief-versus-code discrepancies to carry: the kernel is at
   `crates/kernel/chio-kernel/` (not `kernel/chio-kernel/`), and `ListingSla` /
   `SignedListingPricingHint` live in `chio-listing`'s `discovery.rs` (not a
   `listing.rs` type). The design follows the verified paths.
6. Attempt-fee capture voids the hold remainder through standard rail
   auth-capture semantics; confirm each configured adapter voids rather than
   holds the uncaptured balance, since the kernel path issues a single
   `capture` and no explicit partial release (`validation.rs:1037-1046`).
