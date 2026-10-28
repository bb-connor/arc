# ADR-0016: Authoritative Spend Contract (execution nonce + atomic hold + mediated-spend profile)

- Status: Accepted (2026-10-27)
- Decision owner: kernel and spend control-plane lane
- Related invariant: fail-closed enforcement; "authoritative" is a structural conjunction over the kernel signature, not a label
- Consumed by: the comptroller surface-report contract (`chio.comptroller.surface-report.v1`) and the settlement receipt

## Context

The kernel contains an atomic, fail-closed spend pipeline (`budget_store.rs`
`authorize_budget_hold`, `execution_nonce.rs`, `validation.rs` reconcile).
`TrustLevel::Mediated` is a stamp (`receipt_persistence.rs`), not proof that
budget was held and guards ran, and an advisory receipt states in its own
metadata that it is not authorization. This ADR makes the enforcement contract
normative so downstream consumers can pin to a stable shape. It covers the
`chio.execution_nonce.v1` schema (`execution_nonce.rs`) and the
`BudgetGuaranteeLevel` taxonomy (`budget_store.rs`).

## Decision

1. `chio.execution_nonce.v1` is a signed body of
   `{schema, nonce_id, issued_at, expires_at, bound_to{subject_id, request_id,
   capability_id, tool_server, tool_name, parameter_hash}, reserved_hold_id?,
   reserving_request_id?}` plus a `signature` over its canonical JSON. A missing
   or empty `request_id` is rejected fail-closed. `reserved_hold_id` and
   `reserving_request_id` are present only on the reserve path (the mediated
   evaluate route that reserves a hold for a later reconcile-by-nonce) and are
   omitted otherwise. A nonce is single use: the replay store reserves it once,
   within its signed expiry. The kernel signs every nonce with its classical
   Ed25519 capability key (`KernelConfig::keypair`).
2. The atomic hold lifecycle (authorize worst-case exposure, reconcile down to
   realized spend, reverse on deny) is normative. `BudgetGuaranteeLevel`
   (`single_node_atomic`, `ha_linearizable`, `partition_escrowed`,
   `advisory_posthoc`) is normative and must be truthful: a store never claims a
   level above its real backing (no `ha_linearizable` without a quorum store).
   The levels rank `advisory_posthoc` < `single_node_atomic` <
   `partition_escrowed` < `ha_linearizable`. A consumer pins a floor with
   `receipt_meets_guarantee_floor`, which fails closed on an unrecognized floor
   or an unrecognized receipt level.
3. `chio.mediated_spend.v1` predicate: a receipt is authoritative iff its body
   signature verifies under its embedded `kernel_key` and it satisfies the
   structural conjunction (a) mediated_decision + prevent + observation_outcome
   absent + trust_level mediated + decision Allow; (b) a reconciled
   `BudgetAuthorityReceiptRef` with nonzero exposure against the agent's
   cost-bearing capability, whose `budget_authority.mediated_spend.profile` is
   exactly `chio.mediated_spend.v1`; (c) a kernel-signed execution nonce bound to
   the same capability/server/tool/parameter_hash; (d) the receipt records the
   nonce id (hold <-> nonce cross-bound), and when the nonce names a
   `reserved_hold_id`, that id equals the receipt's committed hold; (e) the
   receipt `kernel_key` is an admitted kernel key and the nonce signature
   verifies under that same `kernel_key`; (f) fail-closed on any missing or
   invalid element. Implemented by
   `chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt`.
4. Signing profiles. Clause (e) compares the nonce signer with the ordinary
   receipt signer, and the two coincide only under the classical floor:
   - `AllowClassical`: the receipt signer is an `Ed25519Backend` over the same
     `KernelConfig::keypair` that signs nonces, so `kernel_key` verifies both
     the receipt and the nonce, and the predicate can hold.
   - `AllowHybrid` and `PqRequired`: `with_hybrid_signing_backend` installs a
     `HybridBackend` (classical plus ML-DSA-65) as the receipt signer, so
     `kernel_key` is the hybrid composite key. The nonce still carries a bare
     Ed25519 signature, which a hybrid key never verifies. Clause (e) fails with
     `NonceSignatureInvalid`, and no receipt from a kernel on either floor is
     authoritative spend.
   An authoritative-spend consumer therefore admits only classical kernel
   receipt keys. A hybrid or PQ kernel produces authoritative spend receipts
   once it signs execution nonces with its receipt-signing backend; the
   predicate stays unchanged.
5. Prepay authority (owned by the kernel enforcement lane, threaded to the
   comptroller surface-report projection and the settlement receipt): the budget
   hold authorizes the grant's worst case, `max_cost_per_invocation`, and
   reconciles down to the realized cost, clamped to the reserved amount (a
   realized cost above the reservation settles at the reservation). A
   `MustPrepay` quote's `quote.quoted_cost` is the amount authorized and captured
   on the payment rail. It must not exceed the grant's per-invocation or
   cumulative cost limit, and a `MustPrepay` call against a grant that declares
   only a cumulative limit is denied. `MustPrepay` capture is preventive: the
   kernel denies a `MustPrepay` intent when no payment adapter is configured,
   and refuses the execution nonce unless capture reports `Settled`. The
   authoritative number the comptroller surface-report projection reports and
   the settlement receipt gate charges is this authorize-then-reconcile pair,
   not either endpoint alone.
6. Reserved linkage slots (populated as `None` in v1): the comptroller
   surface-report contract `chio.comptroller.surface-report.v1` carries
   `execution_nonce_ref: Option<String>` and `hold_ref: Option<String>`
   (`executionNonceRef` and `holdRef` on the wire, omitted when `None`); the
   settlement receipt MUST carry the same two slots.

## Consequences

This ADR is the binding spend contract. It supersedes the "monotonic,
no-refund" text of ADR-0006 (the kernel refunds via reverse and reconcile).
Advisory-only consumption is a machine-visible conformance failure, enforced by
the golden conformance gate in the chio-conformance crate. The comptroller
surface-report and settlement receipt pin to this shape.
