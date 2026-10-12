# chio-agent-web-interop architecture

## Responsibility and boundary

`AgentWebInteropBundle` supplies a passport, graph/policy bytes, optional
signed root graph, and artifact map. `AgentWebVerifierTrust` supplies
passport/kernel/sidecar pins, webhook secrets, checked time and age window,
optional seen IDs, and replay state. `AgentWebInteropReport` lists verified
claims, projections, unsupported claims, and limitations.

The verifier owns projection consistency and receipt authentication. It does
not connect to external services. Subject validators examine supplied
protocol representations; any issuer discovery or original credential
verification required by the host remains upstream of evidence production.

## Structure

`lib.rs` includes `interop.rs`, which defines the public
bundle/trust/report/replay APIs and composes verification. `evidence.rs`
handles graph/byte bindings; `policy.rs` and `claims.rs` handle required and
limited claims. `artifacts.rs` checks envelope signatures, manifests, and
external-subject dispatch. Its protocol submodules and `protocols.rs`
provide protocol-specific field/version checks. Integration tests are split
into envelope, projection, protocol, and input cases.

## Data and control flow

The verifier bounds input work, checks that passport/kernel/sidecar trust
sets do not overlap, authenticates the signed graph root, and validates
baseline commitments. It resolves projection manifests and envelopes, hashes
external subjects, checks protocol/version rules, and re-verifies referenced
receipt signatures and action bindings.

`agent_web_passport_scope_sha256` canonically binds signed root scope while
excluding graph digest and signature to avoid circular envelope bindings. V1
envelope compatibility follows its legacy bindings; v2 adds passport-scope
binding. Read-only verification returns a report; consuming variants commit
the pending webhook batch after every check passes.

## Trust and invariants

The default trust object has no root pins, so the convenience verifier
cannot authenticate a passport. Signature keys carried by documents still
require caller pin membership. External native-authority overreach is
rejected or represented by explicit declared unsupported limitations
according to policy.

The Standard Webhooks projection authenticates
`id.timestamp.body_digest.endpoint_digest` with caller-selected HMAC secret.
It checks age against supplied verifier time and derives a domain-separated
endpoint replay scope. This is the implemented digest projection
representation. Consuming admission requires a replay store for webhook
evidence. In-memory state rejects backwards time, duplicate IDs, and
exhausted positive global/per-scope capacities without evicting live
entries; its lifetime does not survive restart.

## Dependencies

`chio-transaction-passport` supplies root signatures, bounded JSON, and
commitments. `chio-core-types` supplies canonical hashing and signed
receipts. `chio-commerce-order` supplies payment-context shapes for relevant
projections. `hmac`, `sha2`, `base64`, and `hex` implement webhook
projection authentication and replay scopes. `serde`/`serde_json` project
artifact types; no optional features are declared.

## Verification

`tests/agent_web_interop.rs` composes test modules covering root/envelope
tampering, signer-role overlap, protocol version/shape failures, receipt
scope transplants, webhook age/secret/replay behavior, and original-input
limits. Consuming tests exercise atomic replay and report parity. Run `cargo
test -p chio-agent-web-interop --test agent_web_interop`; the library
unit-test target is disabled. The README demonstrates default missing-pin
rejection offline using a compile-time passport fixture.
