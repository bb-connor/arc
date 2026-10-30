# chio-ag-ui-proxy architecture

## Responsibility and boundary

`AgUiProxy` owns signing material, policy configuration, and a mutex-protected
sibling budget registry. The host supplies events, tokens, transport records, issuer
trust, revocation state, and delivery.

Evaluates agent-to-UI events against capability scope and signs event receipts. It
provides transport metadata and counters for SSE and WebSocket embeddings.

## Structure

Public modules are `event`, `proxy`, `receipt`, and `transport`. Proxy submodules
separate configuration, classification, budget seeding, clocks, scope helpers,
decisions, and evaluation.

`ProxyDecision` carries Forward or Block with a reason. `AgUiReceipt` pairs the
signed receipt body with its signature. `Transport` stores SSE/WebSocket metadata
and independent forward/block counters. It supplies no socket loop or delivery
acknowledgment.

## Data and control flow

Evaluation first validates the event boundary and derives classification from event
semantics. A classification mismatch blocks access. Capability verification and
grant matching decide forwarding. Receipt creation binds event metadata and payload
hash. Successful receipt creation increments the appropriate transport counter.

`evaluate` returns InvalidEvent before classification when event identity fields
fail boundary validation. It then derives a server classification, uses that
classification for receipt creation, and blocks a supplied downgrade.
`build_receipt` runs before record_forwarded or record_blocked, so a signing error
returns without counting a successful decision receipt.

## Trust and invariants

Event agent and session strings are caller-supplied metadata; evaluation does not
compare them to transport identity. Supplied tokens require trusted issuer keys,
valid time bounds, supported features, revocation checks, and matching scope.
Aggregate invocation budgets and cumulative approvals are rejected as unavailable.
`try_new` rejects invalid budget snapshots; `new` logs them and initializes an empty
budget registry.

`AgUiProxy::evaluate` validates event identity fields, derives classification,
blocks mismatches, and signs a receipt before updating transport counters.
Capability-bearing events use `verify_capability_full` and event-bound
scope matching.

The sibling budget registry persists for the proxy lifetime. A mutex serializes one
verification step, preventing delegated siblings on different events from receiving
independent fresh headroom. Trusted issuer keys and configured revocation data are
consumed by full capability verification. max_events_per_second remains
configuration metadata; evaluate does not apply a rate limiter from that value.

## Dependencies

`chio-core` supplies capability and cryptographic types. `chio-kernel-core` supplies
verification, scope matching, and sibling budget enforcement. Serde handles event
and receipt representation; tracing records decisions.

## Verification

Tests in `src/proxy.rs` cover missing tokens, untrusted issuers, delegated budgets,
payload spoofing, classification downgrades, and receipt metadata.
`src/transport.rs` tests counter saturation-compatible accounting and serialization.

Run focused library tests from the workspace root:

```bash
cargo test -p chio-ag-ui-proxy
```

proxy.rs tests blocked events without capabilities and untrusted issuers. The
classification tests exercise forged payload classifications and downgrades.
Delegation tests exercise sibling budgets across successive events. transport.rs
tests kind serialization and distinct forwarded/blocked counts.
