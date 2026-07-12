# WS3 Design: Verified-outcome pricing

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see `2026-07-10-agent-economy-program-design.md`)
- Depends on: `chio_credit::obligation`, WS1 durable money movement, and a
  genuine hold/capture/release rail before activation
- Claim track: implementation (artifact and evaluator only until rail
  qualification)
- Branch: `chio/ws3-outcome-pricing` off `main`

## Goal

When activation prerequisites are met, price one tool call on a deterministic
predicate over the exact output delivered to the caller. The kernel evaluates
the predicate, binds every pricing input and the delivered output digest into
the signed receipt, and either captures the full held price on pass or releases
the full hold on failure or evaluation error. Until a real reversible rail is
qualified, WS3 ships only artifacts, pre-dispatch binding, and the pure
evaluator. V1 has no prepayment, attempt fee, partial capture, or subjective
adjudication.

## Ground truth and prerequisites

The existing budgeted finalize path can capture an authorized amount or release
an authorization, but no current in-tree `PaymentAdapter` implements a proven
reversible hold. `X402PaymentAdapter` performs prepaid authorization, while both
`X402PaymentAdapter` and `AcpPaymentAdapter` treat later `capture` and `release`
as local bookkeeping. Neither can refund or release remote funds merely because
its local `release` returned success.

WS3 production wiring therefore requires a verified rail capability contract:

- `authorize` reserves funds without settling them;
- `capture` can settle the full reserved amount exactly once;
- `release` actually removes the reservation without charging;
- the authorization remains valid through execution and finalization; and
- idempotency and reconciliation are covered by WS1's durable journal.

A rail that reports the authorization as already settled, cannot prove release,
or cannot bind payer, payee, amount, currency, and expiry is ineligible.
Therefore the schemas, pure evaluator, receipt binding, and SLA verifier may
land first, but the output-stage hook and all production money movement remain
disabled until a real rail implementation passes the capability and end-to-end
qualification contract below. A mock endpoint or self-declared adapter flag does
not satisfy this gate.

## In scope

1. A pure `chio_listing::outcome` module for the listing-owned predicate,
   pricing validation, evaluator, and SLA arithmetic. Receipt metadata remains
   in `chio-core-types` and penalty admission remains in `chio-open-market`;
   v1 adds no crate.
2. RFC 6901 JSON Pointer selectors with a small deterministic comparator set.
3. One pricing rule: full `outcome_price` on `Passed` and `ZeroCharge` on
   `Failed` or `Unevaluable`.
4. Activation-gated `HoldCapture` requests over an adapter proven to support
   genuine hold, capture, and release.
5. Receipt metadata that binds listing, provider, pricing, predicate, quote,
   delivered output, verdict, and charged amount.
6. An SLA breach artifact whose numerator and denominator are both proven from
   a complete receipt-log range.
7. Schema registration, public verifier coverage, unknown-schema negatives, and
   PROTOCOL reconciliation in the same phase.

## Out of scope

- `MustPrepay`, `AllowThenSettle`, prepaid x402, attempt fees, escrow attempt
  fees, partial capture, and any adapter whose unused balance is only local
  bookkeeping.
- JSONPath, guard-verdict predicates, user code, regex, WASM predicates,
  floating-point comparisons, or model-judged outcomes.
- New Solidity, mainnet or public-testnet deployment, and production money
  movement ahead of WS1.
- Automatic SLA slashing. A breach artifact is complete evidence submitted to
  the existing governance path, not authority to move funds.

## Design

### Predicate vocabulary

`chio.outcome.predicate.v1` contains a non-empty AND-list of assertions. Each
assertion has an RFC 6901 `pointer` and one comparator:

- `exists`;
- `eq` or `ne` against an attached JSON value, compared by RFC 8785 canonical
  bytes; or
- `lt`, `lte`, `gt`, or `gte` against an attached JSON integer, with both
  operands parsed by checked integer conversion.

The empty pointer selects the whole document. Invalid escape sequences,
duplicate assertions, non-integer ordered operands, numeric overflow, missing
targets, invalid JSON, and unknown comparators are deterministic errors.
`exists` passes on any selected value. All other missing targets fail. The
predicate has no extension or reserved execution form in v1.

Evaluation returns `Passed`, `Failed { reason }`, or
`Unevaluable { reason }`. `Failed` and `Unevaluable` both produce zero charge.
The distinction is receipt evidence only.

### Artifacts and receipt binding

All artifacts are signed RFC 8785 canonical JSON with
`deny_unknown_fields` and versioned schema identifiers.

- `chio.outcome.predicate.v1` binds `predicate_id`, assertions,
  `provider_id`, `issued_at`, and `expires_at`.
- `chio.outcome.pricing.v1` binds `pricing_id`, `provider_id`,
  `predicate_id` and digest, `outcome_price: MonetaryAmount`,
  `failure_mode: zero_charge`, optional `sla_digest`, `issued_at`, and
  `expires_at`.
- `chio.outcome.sla.v1` binds provider and listing digests,
  `max_failure_bps <= 10_000`, `minimum_sample_count > 0`,
  `window_seconds > 0`, a fixed window anchor, `effective_at`, and
  `expires_at`. The provider signs the SLA commitment referenced by the listing
  and pricing artifacts.
- `chio.outcome.eligibility.v1` is a pre-dispatch kernel-signed record. Its
  canonical body binds `schema: "chio.outcome.eligibility.v1"`,
  `eligibility_id`, `request_id`, capability id, tool server and tool name,
  provider id, listing id and digest, provider-binding digest, pricing id and
  digest, predicate id and digest, quote digest, optional SLA digest, exact
  `outcome_price`, `HoldCapture`, pre-action authority digest, exact post-guard
  policy digest, and a trusted receiver-binding digest, `issued_at`, and
  `expires_at`. The receiver binding resolves the kernel or edge key plus the
  rollback-independent delivery-anchor identity/namespace authorized to own the
  delivery slot; an embedded acknowledgement key or caller-selected anchor is
  never a trust root. The kernel signs the RFC 8785 body only after validating every
  referenced artifact and before dispatch. The signed artifact envelope contains
  that body and its detached signature; `eligibility_digest` is SHA-256 over the
  RFC 8785 canonical envelope. `eligibility_id` is SHA-256 over the
  domain-separated canonical body excluding `eligibility_id`; the verifier
  recomputes it before accepting the envelope. The record is evidence of the selected pricing
  contract, not a replacement for capability, policy, or guard authority.
- `chio.outcome.dispatch-acceptance.v1` is a provider-signed durable-queue
  acknowledgement binding `schema`, domain-separated `acceptance_id`, request
  id, eligibility digest, parameter hash, provider/listing binding, server queue
  id, idempotency key, provider key id/epoch, and exact externally anchored
  `Accepted` dispatch-checkpoint sequence/digest. The provider key resolves from
  the trusted listing binding. It is valid only when the qualified server has
  durably assumed responsibility to execute exactly once or expose a terminal
  signed outcome through its restart-safe status query. Socket acceptance,
  in-memory enqueue, or synchronous function entry does not qualify.
- `chio.outcome.dispatch-checkpoint.v1` is the provider attempt-slot continuity
  record. Its `ProviderDispatchAnchor` lives outside the provider queue/database
  backup domain and binds provider/anchor identity, namespace, operation/request,
  eligibility and parameter digests, attempt/idempotency key, monotonic slot
  version and predecessor, trusted clock, execution lease/fence, and state
  `Pending | Accepted | Executing | Completed | Cancelled`. The anchor accepts
  only private-verified legal CAS transitions: `Absent -> Pending`, `Pending ->
  Accepted | Cancelled`, `Accepted -> Executing`, and `Executing -> Completed`.
  `Accepted` requires the immutable staged queue row plus a content-addressed
  invocation blob outside the queue restore domain, or a rollback-independent
  availability receipt for that blob. `Executing` assigns one fenced executor.
  `Completed` requires a durable authenticated terminal outcome reference.
  `Cancelled` is permanent and proves the same key can never become accepted or
  execute; `Accepted`, `Executing`, and `Completed` can never cancel.
- `chio.outcome.dispatch-nonacceptance.v1` is provider-signed and binds the exact
  current `Cancelled` dispatch checkpoint. Only that externally continuous proof
  can construct `VerifiedTransportNotAccepted`. A local queue query, missing row,
  timeout, old signed status, or restored/behind/divergent/unavailable anchor view
  is `Unknown`, not no-effect authority.

Provider handoff uses the cross-store protocol `LocalQueuedStaged ->
DispatchAnchorAccepted -> LocalExecutable`. A staged row is permanently
non-executable until a worker reads the exact current external `Accepted`
checkpoint and wins its `Accepted -> Executing` lease/fence CAS. If
`Pending -> Cancelled` wins, every matching staged row becomes permanently
non-executable. Recovery reads the anchor before local queue state. An anchored
`Accepted` row whose local queue was rolled back is reconstructed from the
anchored invocation blob; it is never cancelled. After invocation, the provider
stores the terminal result for authenticated lookup before `Executing ->
Completed`. A crash after an effect but before `Completed` may resume only from
authenticated tool-side status or through a separately qualified idempotent tool
invocation keyed by the same operation, attempt, and execution fence. Without
one of those proofs it remains `Executing`/unknown and does not rerun. Stale
executors are fenced and cannot publish a terminal result.
- `chio.outcome.delivery-acknowledgement.v1` is signed by the trusted receiver
  kernel or edge only after the rollback-independent caller-owned delivery slot
  stores the exact final bytes and atomically advances `Pending -> Acknowledged`,
  and before it exposes them to the agent. It binds `ack_id`, request id,
  eligibility and
  dispatch-acceptance digests, final output digest, receiver-binding digest,
  delivery id and idempotency key, receiver queue id, trusted accepted time, and
  receiver key id/epoch plus exact delivery-checkpoint sequence/digest and durable
  blob reference. The anchor retains restart-queryable retrieval by delivery id,
  so a crash or local mailbox restore after acknowledgement cannot strand paid
  output or reopen cancellation. The signer resolves from the pre-dispatch receiver
  binding. A socket write, HTTP response completion, or caller-supplied key does
  not qualify.
- `chio.outcome.delivery-nonacceptance.v1` is a receiver-signed terminal
  cancellation proof for the same exact request, eligibility, provider
  acceptance, output digest, receiver binding, delivery id, idempotency key and
  receiver queue. The receiver creates it only after the external delivery anchor
  compare-and-swaps the slot from `Pending` to permanently `Cancelled`, proves no
  blob was accepted or exposed, and makes every later write for that delivery key
  reject. It binds the exact cancellation checkpoint sequence/digest. A private
  verifier constructs `VerifiedReceiverNoDelivery`; missing, timed-out or
  unreachable acknowledgement is not this proof.

The `ReceiverDeliveryAnchor` is outside the receiver SQLite/mailbox backup and
restore domain. Its signed `chio.outcome.delivery-checkpoint.v1` binds anchor and
receiver identity, namespace, delivery slot/idempotency key, monotonic slot
version and predecessor digest, state `Pending | Acknowledged | Cancelled`, exact
request/eligibility/acceptance/output bindings, optional content-addressed blob
reference/digest, trusted-clock high-water, and receiver key epoch. The anchor
stores acknowledged blobs durably or verifies a rollback-independent blob-store
availability receipt before advancing.

A private `VerifiedReceiverDeliveryAdvance` enforces one legal transition
(`Absent -> Pending`, `Pending -> Acknowledged`, or `Pending -> Cancelled`),
exact predecessor, version plus one, nondecreasing clock, and unchanged bindings.
`Pending -> Acknowledged` requires the exact durable blob and
`Pending -> Cancelled` requires a blob-absence proof and cancellation fence. The
anchor accepts only this verified type by linearizable compare-and-swap. Delivery
uses `LocalStaged -> AnchorAdvanced -> LocalFinalized`; exposure is forbidden
until the anchored `Acknowledged` state and local view agree. Recovery reads the
anchor first. A local snapshot that is behind or divergent is repaired from the
anchored blob or fails closed; it can never sign nonacceptance. Anchor outage or
an unresolved staged transition is `delivery_unknown`, with no capture or
release.
- `chio.outcome.verdict.v1` receipt metadata binds:
  `listing_id`, `listing_digest`, `provider_id`,
  `provider_binding_digest`, `pricing_id`, `pricing_digest`,
  `predicate_id`, `predicate_digest`, `quote_digest`, `eligibility_digest`,
  `dispatch_acceptance_digest`, tagged `delivery_disposition: acknowledged |
  cancelled | not_attempted`, optional `delivery_acknowledgement_digest`, optional
  `delivery_nonacceptance_digest`,
  optional `delivered_output_digest`, `verdict`, `reason_code`,
  `sla_attribution: provider | caller_policy | platform`, `charged_amount`, and
  `rail_authorization_ref`.

The provider binding identifies the trusted key that must sign the listing,
predicate, and pricing artifacts. The request quote digest covers the entire
canonical `MeteredBillingQuote` and its verified-outcome references. A matching
identifier without a matching digest rejects. Receipt metadata is part of the
kernel-signed receipt and cannot be filled from a tool-server self-report.
`acknowledged` requires only the acknowledgement digest, `cancelled` requires only
the verified nonacceptance digest, and `not_attempted` requires both absent and a
terminal pre-delivery zero-charge reason. `delivery_unknown` emits no success
receipt and cannot be encoded as one of these dispositions.

For an outcome-priced request, the same receipt-store transaction that creates
the RFC-0003 `AdmissionOperation::Prepared` row also persists the canonical
signed eligibility record and writes its digest into the canonical request
binding. The digest is mandatory for this
request class and null for unrelated calls. A duplicate request id with
different eligibility bytes, a missing record, a digest mismatch, an unknown
schema or version, or an untrusted kernel signer denies before dispatch. The
operation and record commit together, so a crash can leave both or neither,
never an unattributed outcome-pricing operation. The eligibility record starts
`prepared`. After authorization and every pre-tool check succeeds, the kernel
must durably compare-and-swap it to `dispatch_started` immediately before the
qualified transport handoff. This is platform state, not provider SLA evidence.
Only a verified durable acknowledgement may transition the row to
`dispatch_accepted`, recording its digest and a trusted local acceptance time.
Receipt commit must supply its digest in the typed
`AdmissionTerminalProjection::Completed`, match the same digest in signed
`chio.outcome.verdict.v1` metadata, and atomically move the record to
`receipt_bound` with the receipt id while retaining the completed operation, and the signed
verdict must bind the same acceptance digest. Terminal crash reconciliation from
`dispatch_accepted` becomes a provider incident; `dispatch_started` without a
recoverable acknowledgement creates a platform incident but remains unresolved
and makes SLA proof incomplete. Only an authenticated server `NotAccepted`
result carrying the current external permanent `Cancelled` checkpoint may
terminate it as `not_dispatched`. A pre-tool abort or recovery moves `prepared` to
`not_dispatched`; that proof is retained but excluded from provider SLA math.
The resolved record and retained terminal operation must agree.

WS3 further extends the operation-owned eligibility lifecycle after provider
acceptance:

```text
dispatch_accepted -> output_ready -> delivery_started
delivery_started -> delivery_acknowledged -> receipt_bound
delivery_started -> delivery_cancelled -> receipt_bound
delivery_started -> delivery_unknown
```

`output_ready` binds the immutable final post-guard bytes and digest.
`delivery_started` binds the exact externally anchored `Pending` slot checkpoint.
`delivery_acknowledged` stores and verifies the canonical receiver
acknowledgement. Only that state may commit a capture action.
`delivery_cancelled` requires `VerifiedReceiverNoDelivery` and commits a release
action plus zero-charge receipt. Missing, expired, ambiguous or unqueryable
acknowledgement moves to `delivery_unknown`, records an incident, freezes the
hold and emits no success receipt; if recovery later declares it irrecoverable,
the retained operation is `OutcomeUnknownAfterDispatch` and the hold remains
frozen. Such ambiguity is neither capture nor release authority. A crash
after acknowledgement but before capture reuses the same operation, delivery id,
and rail idempotency key and captures at most once.

### Exact output-stage ordering

The only valid order is:

1. Verify the listing, provider binding, predicate, pricing, and quote digests
   and validity windows.
2. Build and verify `chio.outcome.eligibility.v1`. Atomically persist it with
   RFC-0003's `AdmissionOperation::Prepared` and bind its digest into the
   canonical request binding. Require `MeteredSettlementMode::HoldCapture` and a qualifying
   rail, authorize an unsettled hold for exactly
   `outcome_price`, and durably record that authorization before dispatch.
3. After every pre-tool check succeeds, capture invocation admission and durably
   persist `AdmissionOperation::DispatchCommitted`. Compare-and-swap eligibility
   from `prepared` to `dispatch_started`, append its immutable lifecycle
   event, then invoke only the qualified durable-acceptance transport. If that
   commit fails, do not invoke transport; reconcile the hold and terminate as
   `not_dispatched`.
4. Verify the provider-bound `chio.outcome.dispatch-acceptance.v1` returned only
   after immutable local staging, rollback-independent invocation-blob
   availability and external `Accepted` checkpoint CAS. Persist
   its bytes/checkpoint digest, assign the trusted local acceptance time, and
   compare-and-swap `dispatch_started` to `dispatch_accepted`. If the
   acknowledgement is lost, recovery queries the external provider slot by exact
   idempotency key and eligibility digest. Only a current permanent `Cancelled`
   checkpoint proves nonacceptance; anchor outage, local restore, or any
   behind/divergent view remains unresolved. Until acceptance is proven, any
   terminal incident is platform-owned and excluded from provider SLA math.
5. The provider worker reads the current external `Accepted` checkpoint, wins
   `Accepted -> Executing` with a fresh execution lease/fence, and only then may
   invoke the tool. Await its authenticated terminal output and retain the raw
   bytes before advancing the anchor to `Completed`. A crash in `Executing`
   queries the exact tool-side idempotency key; absent qualified status or
   idempotent replay, it remains unknown and does not invoke again.
6. Run the complete post-invocation guard pipeline. A block or escalation sets
   `delivered_output_digest = None` and
   `Unevaluable { reason: output_blocked }`, then proceeds to zero-charge
   release with `sla_attribution = caller_policy`. A redaction produces the final
   output bytes and also uses `caller_policy`. Guard/evaluator/store/ordering
   failures use `platform`; no free-form guard label can assign provider fault.
7. For an allowed output, freeze those final bytes as `delivered_output`. Compute
   `delivered_output_digest` and evaluate the predicate over the JSON parsed
   from those same bytes.
8. Run no output mutation after predicate evaluation. Any component that would
   transform the output after this point is an ordering violation. It persists a
   contractual zero-charge outcome before release and never starts delivery.
9. Persist `output_ready` with the final output digest and start the qualified
   two-stage delivery. The receiver verifies the binding, creates the exact
   external `Pending` slot, stages the bytes, advances the delivery anchor to
   `Acknowledged` with rollback-independent blob availability, finalizes its local
   view, signs and durably stores `chio.outcome.delivery-acknowledgement.v1`, and
   only then exposes bytes retrieved from that slot to the agent. The delivery
   remains retrievable by id across restart or local snapshot restore.
10. Persist and verify the acknowledgement, compare-and-swap to
    `delivery_acknowledged`, and set `reported_cost` to the full outcome price
    only for `Passed`. Persist an exact `Capture` settle action. If the
    receiver instead returns a valid anchored delivery-nonacceptance artifact, construct
    `VerifiedReceiverNoDelivery`, transition to `delivery_cancelled`, set cost to
    zero, and persist `Release`. If acknowledgement or nonacceptance is missing,
    expired, ambiguous, or unqueryable, transition to `delivery_unknown`, freeze
    the hold, persist an incident and stop without a success receipt.
11. Execute only that durable rail action through WS1. Pending remains
    recoverable; an incompatible result incidents and never produces success.
12. Build and sign one receipt whose financial charge, all bound digests, output
    digest, delivery acknowledgement or verified nonacceptance, attribution,
    verdict, and rail reference agree.
13. Use RFC-0003's `commit_admission_projection` to verify the eligibility,
    acceptance, delivery, verdict, and payment evidence, transition eligibility
    to `receipt_bound`, append the receipt, and retain the operation as
    `Completed` in one receipt-side transaction. Any mismatch rolls back every
    local projection.

The bytes hashed for predicate evaluation are byte-for-byte the bytes durably
accepted at the receiver boundary. Capture cannot precede that acknowledgement.
The predicate never evaluates a pre-redaction output while charging for a
different delivered result.

### Request and disposition contract

A verified-outcome request has `billing_unit = "verified_outcome"`,
`quoted_units = 1`, `quoted_cost == outcome_price`, and
`settlement_mode = HoldCapture`. `MustPrepay` and `AllowThenSettle` reject
before tool execution.

The hold capture is the per-call settlement attempt, not a precursor to a
second observer dispatch. Zero charge creates no atom. A rail result already
proven `Settled` creates no live atom; if an immutable audit atom is retained,
its separate settlement lifecycle is initialized as `satisfied` in the same
durable transaction. A `Pending` capture may create one immutable
`chio_credit::obligation::ObligationAtom` with an authenticated
`chio_credit::obligation::ObligationDisposition` record set to `per_call`, but
its lifecycle is `settlement_in_flight` and binds the existing capture
idempotency key. Observers may only reconcile that exact operation and must not
start another dispatch. `assigned`, `channelized`, or `clearing_reserved` is a
conflict and prevents the WS3 capture path from running.

### SLA completeness proof

`chio.outcome.sla-breach.v1` binds a provider, listing, pricing, predicate,
declared SLA digest and terms, and the exact closed interval derived from that
SLA's anchor and window cadence. A submitter cannot choose a favorable subrange.
It contains:

- the configured trusted receipt-checkpoint authority key and epoch;
- signed start and end checkpoint digests under that authority;
- the first and last log positions;
- a complete range proof covering every receipt position in the interval;
- the signed RFC-0003 dispatch/recovery checkpoint for the same cutoff, its
  append-only lifecycle-event consistency proof, and the complete global
  provider-acceptance-time range for the declared interval with boundary
  leaves. The proof includes each signed `chio.outcome.eligibility.v1` envelope,
  signed dispatch-acceptance and acknowledgement or nonacceptance delivery
  envelope when present,
  stable eligibility sequence, every
  required lifecycle version and incident class, and bound
  receipt or incident id, plus the corresponding retained admission-operation state,
  so a crash after dispatch cannot vanish from the denominator merely because no
  normal receipt was appended. The verifier, not the submitter, applies the
  provider selector to this complete range;
- the checkpoint's global unresolved-`dispatch_started` root and count, which
  must be zero in v1 before any SLA breach proof is accepted. This conservative
  gate prevents a lost or unavailable acknowledgement outside a chosen range
  from hiding a provider-accepted request;
- the fixed eligibility selector
  (`provider_binding_digest`, `listing_digest`, `pricing_digest`, and
  `predicate_digest`);
- the complete eligibility-record root and count, `accepted_count`,
  `provider_attributable_count`, `caller_policy_excluded_count`,
  `platform_excluded_count`, `provider_failure_count`, and references for every
  accepted receipt or terminal incident. The three attribution partitions must
  sum exactly to `accepted_count`; and
- `failure_bps`.

The verifier pins the checkpoint signer and epoch from trusted configuration,
checks checkpoint signatures, authority epochs, append-only event-prefix
consistency, state-root replay, time-range boundaries, and counts. It verifies
that both receipt and eligibility ranges have no missing position, verifies
every eligibility and acceptance signature plus authenticated lifecycle
version, and enforces exactly one terminal binding per record. `prepared`,
`not_dispatched`, `dispatch_started`, and platform-incident records have no
provider-acceptance-time leaf. Terminal `not_dispatched` records are excluded;
an unresolved `dispatch_started` record makes any potentially overlapping proof
incomplete; v1 enforces this as a global zero-count gate. They remain visible in the record/event roots so exclusion cannot
hide an accepted request. A
`dispatch_accepted` record must have its exact digest-bound nonterminal operation and makes
the corpus incomplete until terminal. A
`receipt_bound` record must resolve its recorded receipt id and
the receipt's signed verdict metadata must carry the same eligibility and
  acceptance and delivery digests. A provider-class `incident_bound` record must resolve its
  recorded terminal incident, signed acceptance, and retained operation incident.
A platform-class incident cannot enter the acceptance index. It joins by request
id and digest without double counting,
then replays the selector from the eligibility bodies and
recomputes every partition and count. A missing, tampered,
unknown-schema, expired-at-dispatch, or
selector-mismatched eligibility record makes the corpus incomplete and rejects
the breach artifact; it is never silently excluded. The denominator is
every provider-attributable matching request in the declared window. Provider
attribution is limited to an unmodified delivered provider output that passes or
fails the predicate, invalid provider JSON, or a post-acceptance provider
incident. Guard block or byte-changing redaction is `caller_policy`; delivery,
guard-runtime, evaluator, store, and ordering failures are `platform`. Those
rows remain visible and counted in their excluded partitions but enter neither
the provider numerator nor denominator. An unresolved operation or delivery
state makes the corpus incomplete; a provider-attributable terminal
outcome-unknown incident counts as failed rather than disappearing. Failure
receipts alone are never a valid denominator. An unavailable range proof,
untrusted checkpoint authority, gap, duplicate request or position, zero or
below-minimum denominator, SLA/window mismatch, or ineligible receipt rejects
the artifact.

`failure_bps = provider_failure_count * 10_000 /
provider_attributable_count` uses
checked `u128` arithmetic and must be at most 10,000. It is a display value and
never saturates. Breach authority uses the exact checked cross-product, not the
floored display value:

```text
provider_failure_count * 10_000 > max_failure_bps * provider_attributable_count
```

The artifact is a breach only when that inequality holds and
`provider_attributable_count >= minimum_sample_count`. Thus one provider failure in three attributable requests
breaches a 3,333 bps maximum, while one in four does not breach an exact 2,500
bps maximum.

### Fail-closed errors

Missing or expired artifacts, missing or tampered outcome eligibility, untrusted
eligibility signer, operation/eligibility mismatch, untrusted or mismatched provider
signatures, identifier/digest mismatch, quote mismatch, non-`HoldCapture` mode,
prepaid or unproven rail semantics, authorization mismatch, unknown comparator,
invalid pointer, invalid JSON, output-stage reordering, missing or untrusted
receiver binding, missing/stale/replayed/mismatched delivery acknowledgement,
invalid delivery-nonacceptance or cancellation fence, capture before
acknowledgement, release on delivery ambiguity, charge above the hold,
mixed currency, arithmetic failure, a second dispatch for an in-flight capture,
incomplete SLA range, untrusted checkpoint authority, insufficient sample,
threshold mismatch, and disposition conflict all reject. A runtime predicate
evaluation error after dispatch requests release only after the post-return
journal durably records terminal `Unevaluable` and constructs
`VerifiedContractualZeroCharge`; an ambiguous or non-replayable evaluation
freezes the hold. Until release is proven, reconciliation stays Pending or
Failed. It never records a full charge.

## Alternatives considered

1. A new `chio-outcome` crate was rejected for v1. `chio-listing` already owns
   provider-signed listing pricing; `chio-core-types` and `chio-open-market`
   retain their existing receipt and penalty boundaries. Extract only if a real
   dependency or release boundary appears.
2. Prepayment was rejected because a later local `release` is not a refund.
   Add it only after a configured rail proves outcome-contingent refund
   semantics and WS1 journals that refund.
3. Attempt fees were rejected because they require proven partial capture and
   release of the remainder on every rail. Zero or full capture is the only
   portable v1 contract.
4. JSONPath, output guards, and WASM were deferred. RFC 6901 plus deterministic
   comparators covers the first useful case without a second evaluator or ABI.
5. Failure-only SLA evidence was rejected because a provider can omit
   successful or failed receipts and change the rate. A complete checkpointed
   range is required.

## Claim framing

A `Passed` verdict means only that the exact delivered JSON satisfied the
declared deterministic predicate. It does not prove objective value or factual
correctness. The verdict is kernel-observed receipt evidence. Escrow and payment
payloads remain subordinate rail evidence. No production outcome-priced payment
claim exists until a real reversible rail passes the activation qualification;
the current in-tree adapters do not. It also requires a qualified two-stage
receiver path; returning output and receipt in one `ToolCallResponse` is not
durable delivery acknowledgement.

## Testing strategy

- Predicate table tests for pointer escaping, root selection, missing paths,
  canonical equality, checked integer ordering, invalid numbers, and unknown
  comparators.
- Eligibility: signed canonical positive; mutate each provider/listing/pricing/
  predicate/quote/authority digest independently; reject unknown
  family/schema/version, untrusted signer, duplicate request with different
  bytes, missing operation binding, missing record, and a record committed separately
  from its operation. Creation assigns stable record/event sequences and a
  version-zero `prepared` event. Tool dispatch cannot run before the durable
  `dispatch_started` CAS, but that state alone is platform-owned. Only a signed,
  provider-bound, restart-queryable durable acknowledgement produces
  `dispatch_accepted`. Receipt commit with the right eligibility, acceptance, and
  delivery digests atomically produces `receipt_bound` and retains the completed
  operation; a missing or wrong
  verdict/key digest, stale version/lifecycle, or changed envelope rolls back
  both plus the receipt append. Pre-tool failures produce retained
  `not_dispatched` evidence and never enter the SLA numerator or denominator;
  terminal reconciliation after acceptance atomically produces a provider-class
  `incident_bound`; pre-acceptance handoff failures produce platform incidents,
  and ambiguous acceptance remains unresolved until a trusted query resolves it.
  Resolved records remain queryable with the terminal operation; only creation of
  a `prepared` record without its operation rejects.
- Rail matrix: no current in-tree adapter activates WS3. A future genuine
  unsettled hold passes only after networked authorize/capture/release,
  idempotent replay/query, expiry, amount, payer, payee, currency, and durable
  reconciliation qualification. Already-settled `X402PaymentAdapter`,
  `AcpPaymentAdapter` local bookkeeping, missing release proof, expired
  authorization, and binding mismatch reject before dispatch.
- Provider transport matrix: no generic in-tree tool server activates WS3. A
  future server passes only after durable enqueue before acknowledgement,
  exact-once/idempotency-key enforcement, provider-key binding, and a
  rollback-independent `ProviderDispatchAnchor` whose signed slot checkpoints
  bind the exact operation, attempt, predecessor, version and terminal outcome.
  Local queue staging must be non-executable until the external `Accepted ->
  Executing` lease/fence CAS, and external `Cancelled` must permanently fence the
  staged row. Accepted invocation bytes remain reconstructible outside the local
  queue restore domain.
  Acceptance-loss recovery must read the current external `Accepted` or
  `Completed` checkpoint. Nonacceptance requires the current permanent external
  `Cancelled` checkpoint and its cancellation fence. In-memory enqueue, socket
  acceptance, unsigned acknowledgement, wrong
  provider/eligibility/parameter digest, local queue absence, an old checkpoint,
  and a behind, divergent or unavailable anchor cannot create acceptance or
  no-effect evidence. Race staged enqueue against cancellation and executor claim
  against cancellation; exactly one external CAS wins and a cancelled row never
  executes. Crash and restore the provider before and after local stage, external
  acceptance, executor claim, tool effect, terminal-result persistence and
  completion CAS. After an effect but before `Completed`, only authenticated
  tool-side status or qualified idempotent invocation may finish the same
  attempt; otherwise the operation remains `OutcomeUnknownAfterDispatch` with
  its hold frozen and is not rerun. A restored local database can never
  manufacture `NotAccepted`.
- Receiver delivery matrix: the receiver kernel durably stores the exact bytes
  in the rollback-independent anchored slot before acknowledgement and exposure.
  Wrong receiver key/epoch, anchor identity/namespace, checkpoint predecessor,
  slot version, request,
  eligibility, acceptance, output digest, delivery id, or replayed acknowledgement
  rejects. A crash after acknowledgement but before capture resumes one capture;
  a lost, expired, or unqueryable acknowledgement freezes the hold and remains
  unresolved. Only a receiver-signed no-delivery result created atomically with a
  permanent anchored cancellation tombstone releases. Forged, stale, wrong-key,
  wrong-delivery, post-acceptance and replaceable cancellation proofs reject.
  Crash and restore the receiver to every point before and after blob stage,
  anchor CAS, local finalize, signed ack, and exposure. A restored pre-ack local
  snapshot observes the anchored acknowledgement and cannot cancel; an anchor
  outage/behind/divergent view remains delivery-unknown.
- Ordering: predicates see redacted delivered bytes; a post-predicate mutation
  releases and rejects; the receipt output digest equals the acknowledged bytes.
- Pricing: an acknowledged pass captures exactly the quoted price; fail,
  unevaluable, and verified cancelled delivery release the entire hold;
  delivery-unknown freezes it and emits no success receipt. No code path emits an
  attempt fee. A settled capture creates
  no outstanding atom, and a pending capture can only reconcile its original
  idempotency key.
- Binding: mutate each of listing, provider, pricing, predicate, or quote digest
  independently and assert denial.
- SLA: omit, duplicate, or reorder one receipt or eligibility position and
  assert rejection; prove the attribution partitions sum to `accepted_count`,
  provider numerator and denominator recomputation, and the 0 and
  10,000 basis-point boundaries. Wrong checkpoint signer/epoch, cherry-picked window, insufficient
  sample, and an exact rate at or below the declared maximum are not breaches.
  Fractional boundaries prove the cross-product rule: 1/3 breaches 3,333 bps,
  and 1/4 equals but does not breach 2,500 bps. Lifecycle tests mutate or omit an
  event version, state-root leaf, acceptance-time-index boundary,
  prior-checkpoint digest,
  unresolved-started root/count, or sequence and reject. Any nonzero unresolved
  count rejects the SLA proof. A pre-authorization failure, authorization denial,
  and confirmed release before `dispatch_started` remain visible as
  `not_dispatched` but do not change the denominator. A crash immediately after
  `dispatch_started` becomes a platform incident and blocks SLA proof until an
  external current `Accepted`, `Completed`, or permanently `Cancelled` dispatch
  checkpoint resolves it. A restored local `NotAccepted`, missing provider row,
  or unavailable, behind or divergent anchor leaves it unresolved; a crash
  after verified durable `dispatch_accepted` is incomplete until terminally
  reconciled. Guard block/redaction and platform/delivery failures remain visible
  in excluded partitions; only a provider-attributable incident counts as a
  provider failure. Omitting any partition leaf rejects. A request prepared in one SLA
  window and accepted in the next belongs only to the latter.
- Exclusive routing, schema registry parity, public verifier positives,
  unknown-schema negatives, and the workspace gate.

## Implementation phases

1. Land the pure `chio_listing::outcome` predicate, pricing, eligibility,
   dispatch-acceptance, delivery-checkpoint, delivery-acknowledgement,
   delivery-nonacceptance, verdict,
   attribution, and SLA validators with schemas, runtime/CLI registry parity,
   signed/tampered fixtures, and unknown-schema negatives.
2. Add the atomic RFC-0003 operation/eligibility binding and pure exact-output
   evaluator. Keep the output-stage payment hook disabled.
3. Only after a real rail passes genuine reversible-rail qualification and a
   provider transport passes durable enqueue, signed acceptance, exact
   idempotency, non-executable local staging, rollback-independent invocation
   blob and dispatch-slot continuity, executor lease/fencing, external
   acceptance/completion/cancellation status query, restart-after-enqueue,
   restart-after-execution, and lost-ack qualification, and a receiver path
   passes rollback-independent slot/blob continuity,
   durable-store-before-expose, signed acknowledgement/nonacceptance, status-query,
   crash/restore, anchor-outage, and wrong-binding qualification, enable the hook. Wire
   full-capture/zero-release through WS1's durable participant plus the RFC-0003
   acceptance/delivery lifecycle, and add the always-on
   receipt/output/rail/acceptance/delivery proof. No current in-tree adapter,
   generic tool server, or one-stage `ToolCallResponse` satisfies this phase entry.
4. Add SLA aggregation only after complete checkpoint range proofs exist.
