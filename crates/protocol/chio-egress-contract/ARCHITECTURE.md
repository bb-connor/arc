# chio-egress-contract architecture

## Responsibility and boundary

Defines tenant-scoped HTTP egress policy and reusable URL, DNS, redirect, and
response-size checks for Chio adapters.

Implemented contract validation with optional reqwest transport enforcement.
Callers own tenant policy selection and must use the enforcing APIs on their
actual dispatch path. `permissive_for_tests` is intended for test fixtures.

## Structure

`lib.rs` defines raw and prepared contracts, target results, and error types.

URL normalization and IP classification helpers live beside enforcement.

`reqwest_helper` is enabled by `reqwest-egress` and handles HTTP dispatch.

`operator_readiness` exports feature-gated readiness probes.

`tests.rs` and `operator_readiness_tests.rs` contain policy and transport tests.

## Data and control flow

Construct a raw contract from tenant policy. `prepare` validates nonempty
namespace and allowlists, supported schemes, canonical authorities, and
a positive response ceiling, then clones the validated policy.

URL enforcement parses the target, rejects userinfo, checks the redirect
count, and matches normalized authority and address classes. DNS enforcement
resolves domain names and checks every returned address.

With `reqwest-egress`, build a `ContractClient` using
`client_builder_with_contract` and dispatch through `send_with_contract`.
`ContractClient` keeps its reqwest client private and exposes request
construction but no dispatch, and `send_with_contract` accepts no other
client type. The client never retries and never follows redirects. The helper
drives redirects explicitly and collects response chunks under the declared
byte ceiling.

## Trust and invariants

Serialization yields policy data. It carries no signature or kernel
authorization. A prepared handle preserves policy after raw-contract mutation.

Loopback and link-local denial follow their configured flags. Private, IPv6
ULA and special-use classes covered by the classifier deny regardless of
explicit authority entries; only a pinned private network allowance reaches a
private or ULA address. IPv4-mapped IPv6 follows IPv4 classification.

DNS checks on a URL alone do not bind a later independent connection.
The contract client installs a checking resolver and disables proxies and
automatic redirects. Use that client with the dispatch helper to retain
those connection protections. Response checks require actual observations.

## Dependencies

`url` parses and normalizes targets. Serde encodes policy data and thiserror
represents denials. Optional reqwest and Tokio implement asynchronous dispatch;
optional core and JSON dependencies decode untrusted helper responses.

## Verification

Tests cover canonical authorities, default ports, immutable snapshots, address
classes, missing policy, redirects, credential filtering, and streaming size
limits. Feature-gated transport tests use local HTTP fixtures.

Run the focused crate suite from the workspace root:

```bash
cargo test -p chio-egress-contract
```

See the [README](README.md) for a minimal public API example and requirements.
