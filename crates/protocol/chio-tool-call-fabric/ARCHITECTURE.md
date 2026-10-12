# chio-tool-call-fabric architecture

## Responsibility and boundary

Defines provider-neutral tool invocations, provenance signatures, adapter traits,
and buffered stream transitions used by Chio provider integrations.

Implemented shared contracts and stream state machine. Standalone provenance
verification returns the signing key; callers decide whether that key is trusted.
The schema-subsumption property currently checks structural fields.

## Structure

`types` defines providers, principals, invocations, verdicts, and validation.

`adapter` defines `ProviderAdapter` and provider request/response contracts.

`provenance` signs and verifies standalone provenance envelopes.

`stream` defines buffered blocks, events, phases, and transition errors.

`error` defines provider errors; `lib.rs` reexports the shared API.

## Data and control flow

An adapter lifts provider-native requests into `ToolInvocation` values.
The invocation carries canonical argument bytes, provenance, and optional
manifest registry security metadata for downstream admission.

Consumers call `validate` before using data crossing a trust boundary.
The host obtains a kernel verdict and the adapter lowers that verdict
into provider-native responses through the shared trait contract.

Streaming phases buffer tool-call data and process verdict events.
Transition callers control forwarding and execution. Standalone provenance
can be signed for later audits without embedding a full receipt.

## Trust and invariants

Public struct construction and Serde decoding do not automatically run
`ToolInvocation::validate`. Validation limits argument bytes to 1 MiB,
rejects duplicate or noncanonical JSON, and requires an object. Identity
fields must be nonempty, unpadded, and free of control characters.

Optional bridge metadata must have registry coordinates and match the
invoked tool name. Live registry admission and capability enforcement remain
responsibilities of the consuming kernel integration.

Provenance signing canonicalizes the stamp. Verification matches the
algorithm, canonical bytes, and signature, then returns the signing key.
It does not establish provider-account ownership or trust in that key.
Direct `BufferedBlock::append` is unbounded; use bounded phase transitions.

## Dependencies

Core types supply canonical JSON and cryptographic signing backends.
`chio-manifest` supplies bridge security metadata and server-tool names.
Security types support shared adapter authority contracts. Serde and
async-trait define wire data and asynchronous adapter interfaces.

## Verification

Unit tests cover provider serialization, invocation validation, provenance
tampering, and stream limits. Integration tests cover lift/lower fixtures,
stream transitions, and property invariants. Schema subsumption remains
a structural self-check even when its feature is enabled.

Run the focused crate suite from the workspace root:

```bash
cargo test -p chio-tool-call-fabric
```

See the [README](README.md) for a minimal public API example and requirements.
