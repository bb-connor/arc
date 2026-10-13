# ADR-0016: Authoritative Spend Contract (execution nonce + atomic hold + mediated-spend profile)

- Status: Accepted 2026-10-13 (owner decision register, unified roadmap section 8). On acceptance the decision text was checked against main and corrected where the code differs; see [Acceptance review](#acceptance-review-2026-10-13).
- Decision owner: kernel and spend control-plane lane
- Related invariant: fail-closed enforcement; "authoritative" is a structural conjunction over the kernel signature, not a label
- Consumed by: the comptroller surface-report contract (`chio.comptroller.surface-report.v1`) and the settlement receipt

## Context

The kernel already contains an atomic, fail-closed spend pipeline (`budget_store.rs`
`authorize_budget_hold`, `execution_nonce.rs`, `validation.rs` reconcile). The
surface real agents use (the `chio-api-protect` sidecar direct tool-call route)
routed around it and emitted an advisory receipt that admits, in its own
metadata, that it is not authorization. `TrustLevel::Mediated` is a stamp
(`receipt_persistence.rs`), not proof that budget was held and guards ran. This
ADR declares the enforcement contract normative so downstream consumers can pin
to a stable shape.

Two code-only realities are hereby reconciled with the docs: the
`chio.execution_nonce.v1` schema (`execution_nonce.rs`) and the
`BudgetGuaranteeLevel` taxonomy (`budget_store.rs`) were previously absent from
`spec/` and every ADR.

## Decision

1. `chio.execution_nonce.v1` is a signed body of
   `{schema, nonce_id, issued_at, expires_at, bound_to{subject_id, request_id,
   capability_id, tool_server, tool_name, parameter_hash}, reserved_hold_id?,
   reserving_request_id?}` plus a `signature` from the kernel's receipt-signing
   key, over the canonical JSON body. A missing or empty `request_id` is
   rejected fail-closed. `reserved_hold_id` and `reserving_request_id` are
   present only on the reserve path (the mediated evaluate route that reserves a
   hold for a later reconcile-by-nonce) and are omitted from the body otherwise.
   A nonce is single use: the replay store reserves it once, within its signed
   expiry.
2. The atomic hold lifecycle (authorize worst-case exposure, reconcile down to
   realized spend, reverse on deny) is normative. `BudgetGuaranteeLevel`
   (`single_node_atomic`, `ha_linearizable`, `partition_escrowed`,
   `advisory_posthoc`) is normative and must be truthful: a store never claims a
   level above its real backing (no `ha_linearizable` without a quorum store).
   The levels rank `advisory_posthoc` < `single_node_atomic` <
   `partition_escrowed` < `ha_linearizable`. A consumer may pin a floor with
   `receipt_meets_guarantee_floor`, which fails closed on an unrecognized floor
   or an unrecognized receipt level.
3. `chio.mediated_spend.v1` predicate: a receipt is authoritative iff its body
   signature verifies under its embedded kernel key and it satisfies the
   structural conjunction (a) mediated_decision + prevent + observation_outcome
   absent + trust_level mediated + decision Allow; (b) a reconciled
   `BudgetAuthorityReceiptRef` with nonzero exposure against the agent's
   cost-bearing capability, whose `budget_authority.mediated_spend.profile` is
   exactly `chio.mediated_spend.v1`; (c) a kernel-signed execution nonce bound to
   the same capability/server/tool/parameter_hash; (d) the receipt records the
   nonce id (hold <-> nonce cross-bound), and when the nonce names a
   `reserved_hold_id`, that id equals the receipt's committed hold; (e) the
   receipt signer is an admitted kernel key and the nonce is signed by that same
   key; (f) fail-closed on any missing or invalid element. Implemented by
   `chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt`.
4. Prepay authority (owned by the kernel enforcement lane, threaded to the
   comptroller surface-report projection and the settlement receipt): the budget
   hold authorizes the grant's worst case, `max_cost_per_invocation`, and
   reconciles down to the realized cost, clamped to the reserved amount (a
   realized cost above the reservation settles at the reservation). A
   `MustPrepay` quote's `quote.quoted_cost` is the amount authorized and captured
   on the payment rail; it must not exceed the grant's per-invocation or
   cumulative cost limit, and a `MustPrepay` call against a grant that declares
   only a cumulative limit is denied. The authoritative number the comptroller
   surface-report projection reports and the settlement receipt gate charges is
   this authorize-then-reconcile pair, not either endpoint alone.
5. Reserved linkage slots (populate as `Option::None` until a v2 schema revision
   so no governance-gated schema v2 is forced): the comptroller surface-report
   contract `chio.comptroller.surface-report.v1` MUST carry
   `execution_nonce_ref: Option<String>` and `hold_ref: Option<String>`
   (`executionNonceRef` and `holdRef` on the wire, omitted when `None`); the
   off-chain settlement receipt `chio.settle.offchain_receipt.v1` MUST carry the
   same two slots (`execution_nonce_ref` and `hold_ref` on the wire).

## Consequences

Supersedes the "monotonic, no-refund" text of ADR-0006 (the code already refunds
via reverse/reconcile). Advisory-only consumption becomes a machine-visible
conformance failure, enforced by the golden conformance gate in the chio-conformance
crate. The comptroller surface-report and settlement receipt pin to this shape once
the authoritative-spend conformance gates pass.

## Acceptance review 2026-10-13

Before acceptance the decision text was compared with main. The code is the
reference, and these corrections bring the text into line with it:

- Decision 1: the signed nonce body also carries the optional
  `reserved_hold_id` and `reserving_request_id` fields
  (`chio_core_types::message::ExecutionNonce`), and the signing key is the
  kernel's receipt-signing key, not a fixed algorithm.
- Decision 2: the guarantee-level ranking and the fail-closed floor check
  (`receipt_meets_guarantee_floor`) were missing.
- Decision 3: the predicate also verifies the receipt body signature, requires
  the pinned `chio.mediated_spend.v1` profile inside the budget-authority block,
  checks the nonce's reserved hold against the receipt's hold, and requires the
  nonce to be signed by the receipt's own kernel key.
- Decision 4: the budget hold always authorizes `max_cost_per_invocation`
  (`kernel/validation.rs`); `quote.quoted_cost` is the payment-rail prepay
  amount, not the hold amount. Reconciliation clamps realized cost to the
  reservation (`kernel/reconciliation.rs`).
- Decision 5: the slots exist on `ComptrollerSurfaceReport` and on
  `OffchainSettlementReceiptArtifact`; their wire names are now stated.
