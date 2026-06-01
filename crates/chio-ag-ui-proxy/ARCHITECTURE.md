# chio-ag-ui-proxy Architecture Notes

## Module Boundaries

`event.rs` owns the AG-UI event wire model: event identity, type,
classification, target component, and opaque payload. `proxy.rs` owns policy
evaluation, capability verification, budget admission, event classification,
transport accounting, and receipt construction. `receipt.rs` owns canonical
payload hashing plus AG-UI receipt signing and verification. `transport.rs`
owns connection metadata and forwarded or blocked counters. `lib.rs` exposes
the public facade without hiding those modules.

## Pain Points

`proxy.rs` is the dominant file and combines boundary validation, policy
derivation, capability scope matching, budget accounting, and tests. The
highest-risk issue is not line count alone: `AgUiProxy::evaluate` currently
trusts caller-supplied event identifiers before using them in receipt ids,
payload-scope arguments, audit metadata, and transport decisions. Empty
`event_id`, `agent_id`, session ids, or target component fields can therefore
reach receipt construction or scope comparison as if they were meaningful
protocol identities.

## Security and API Constraints

AG-UI receipts are observational and must never imply Chio authorization.
Restricted events must continue to require trusted capability issuers, valid
chain binding, scope containment, and sibling-sum budget admission. Public type
names and module exports should remain source-compatible. Canonical payload
hashing and signature verification must stay byte-stable. Invalid event
identity data should fail closed before the proxy signs a receipt whose
correlation fields are unusable.

## Affected Dependents

No transitive crate edits are expected. `chio-ag-ui-proxy` is consumed as a
public facade by tests and potential product code through `AgUiProxy`,
`AgUiEvent`, `TargetComponent`, `ProxyDecision`, `AgUiReceipt`, `Transport`,
and `TransportKind`. Tightening event-boundary validation should preserve those
types while changing malformed-event behavior from receipt-producing decisions
to `AgUiProxyError::InvalidEvent`.

## Planned Material Improvement

Move event identity validation into `event.rs` and have `AgUiProxy::evaluate`
invoke it before classification, capability checks, transport counters, or
receipt signing. Require non-empty `event_id` and `agent_id`; require optional
`session_id`, `target.component_type`, and `target.component_id` values to be
non-empty when present. This makes AG-UI event identity a real protocol
boundary invariant instead of an implicit assumption inside receipt and scope
logic.
