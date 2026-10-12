# chio-http-core architecture

## Responsibility and boundary

The crate exposes `ChioHttpRequest`, `CallerIdentity`, `AuthMethod`,
`SessionContext`, `Verdict`, `HttpReceipt`, and `HttpAuthority`. It also
exports framework-neutral approval, emergency, compliance, plan, and
regulatory handlers plus route registrations. HTTP hosting, credential
verification, body measurement, and actual forwarding are consumer
responsibilities.

`HttpAuthorityInput` binds route/method, caller, query, optional body
digest, capabilities, projected tool identity/arguments, model metadata,
authorization extensions, and an execution nonce. `SessionContext` carries
counters and optional expiry; hosts must maintain it across requests.

## Structure

`authority.rs` builds an embedded kernel and coordinates preparation,
decision signing, and receipt finalization. `authority_projection.rs` binds
HTTP paths and projected tools to the kernel request. `request.rs`,
`identity.rs`, `method.rs`, `session.rs`, `verdict.rs`, and `receipt.rs`
define shared models.

`approvals.rs`, `emergency.rs`, `compliance.rs`, `plan.rs`, and
`regulatory_api.rs` implement administrative/read interfaces. `routes.rs`
provides registration data; `input.rs` decodes bounded original JSON.
`metrics.rs` reports latency and verdict counts. `egress.rs` re-exports the
separate egress contract.

## Data and control flow

The builder accepts a clock, durable receipt/revocation/admission stores,
approval store, and trusted capability issuers. `prepare` uses the kernel
authority clock, computes identity/content bindings, checks capability hints
and scopes, and runs mediated authorization. `evaluate` adds a signed
decision receipt and updates outcome metrics.

`finalize_receipt` and `finalize_decision_receipt` record final transport
outcome and receipt links after execution. Decision-scope and final-scope
status metadata distinguish these stages. Optional strict execution nonces
bind preflight to completion. Framework hosts perform transport work between
evaluation and finalization.

## Trust and invariants

Presented capabilities are decoded through the original JSON boundary,
verified against selected issuer keys, and checked for expiry, revocation,
and requested grant bindings. Unsupported governed
intent/approval/supplemental fields are retained for explicit rejection.
`CallerIdentity` serialization carries a verified flag; decoding it does not
authenticate credentials.

Request hashes bind the method, route pattern, actual path, query, and
supplied body hash. Receipt verification checks semantic validity and
canonical receipt identity against the embedded key. Trusted-kernel identity
still requires external pins. Ordinary constructors fail mediation without
durable state; `new_ephemeral` deliberately permits in-memory operation.
Session model expiry uses wall time; authoritative capability evaluation
uses the configured kernel clock.

## Dependencies

`chio-kernel` supplies mediation, stores, clocks, and nonce handling.
`chio-core-types` supplies signatures and canonical receipt/request
primitives. `chio-cross-protocol` supplies authoritative route selection.
`chio-security-types`, `chio-egress-contract`, and `chio-metrics-spec`
supply clocks/security interfaces, egress restrictions, and metric names.
`reqwest-egress` exposes optional request-sending helpers.

## Verification

Tests cover capability-input provenance, authority/security binding,
execution nonces, final receipt links, egress contracts, administrative
endpoints, plan evaluation, and signed regulatory exports. Authority unit
tests cover durability errors and invalid capabilities on safe routes. Run
`cargo test -p chio-http-core`; use `--features reqwest-egress` to include
the optional helpers. The README default-feature example selects ephemeral
state and never sends a network request.
