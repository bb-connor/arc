# chio-cross-protocol Architecture Notes

## Module Boundaries

`lib.rs` currently owns the public cross-protocol contract surface end to end:
target protocol discovery, route planning, capability reference projection,
orchestrator execution, target executor handoff, route evidence, and trace
construction. The crate is intentionally a shared substrate for protocol edge
crates rather than a product surface, so source compatibility of public structs
and traits matters.

## Pain Points

The orchestrator builds signed receipt metadata from request identity fields
and caller-provided capability references before enforcing a local lineage
boundary. Empty `origin_request_id`, `kernel_request_id`, `target_server_id`,
`target_tool_name`, or `agent_id` values can flow into bridge ids, route
selection ids, trace contexts, and kernel requests. A source envelope can also
provide a `capabilityRef` whose `chioCapabilityId` matches the active
capability but whose `parentCapabilityHash` does not match the actual
capability lineage.

## Security and API Constraints

The orchestrator must fail closed before signing or forwarding misleading
lineage. Route selection evidence, trace ids, receipt metadata, and capability
envelope fields must remain canonical and byte-stable for valid requests.
Public type names, trait methods, and struct fields should remain
source-compatible. Native and registered target execution must continue to
route through the kernel as before.

## Affected Dependents

No transitive crate edits are expected. Edge crates using
`CrossProtocolOrchestrator`, `CapabilityBridge`, `TargetProtocolExecutor`, and
`CrossProtocolExecutionRequest` keep the same API. Malformed requests change
from kernel/routing behavior to `BridgeError::InvalidRequest` at the shared
orchestrator boundary.

## Completed Boundary Validation Baseline

Added an orchestrator-owned execution boundary validation step before capability
reference injection, route planning, trace construction, or kernel execution.
Required non-empty request identity fields and verified any supplied
`CrossProtocolCapabilityRef` against both the active capability id and the
deterministic parent capability hash. This turns lineage data from trusted
caller metadata into a checked shared invariant.

## Source Protocol Continuity Slice

### Current Boundary

- `CapabilityBridge::source_protocol` is the authoritative protocol family for
  the inbound edge executing through the shared orchestrator.
- `CrossProtocolCapabilityRef::origin_protocol` is deserialized from inbound
  request metadata when a protocol edge supplies a prior bridge reference.
- `OrchestratedToolCall::metadata` signs both `sourceProtocol` and the
  accepted `capabilityRef` into bridge metadata.

### Pain Point

The existing capability-reference validation checks the active capability id
and deterministic parent capability hash, but it does not check that a
supplied `capabilityRef.originProtocol` matches the actual
`CapabilityBridge::source_protocol`. A request entering through A2A can
therefore carry an ACP-origin capability reference whose id and parent hash are
otherwise valid. That creates contradictory signed bridge metadata and weakens
receipt lineage even though the orchestrator knows the real inbound protocol.

### Security And API Constraints

- Preserve public structs, trait methods, serialized field names, and valid
  receipt metadata bytes for correctly labeled inbound requests.
- Reject source-protocol drift before capability reference injection, route
  planning, trace construction, target execution, or receipt signing.
- Keep existing capability-id and parent-hash mismatch errors stable.
- Do not trust protocol-edge metadata when it disagrees with the bridge object
  selected by the caller.

### Affected Dependents

- `chio-a2a-edge`, `chio-acp-edge`, and `chio-acp-proxy` keep the same public
  API and valid request behavior.
- Malformed bridged requests with a valid capability id/hash but drifted
  `originProtocol` now fail closed with `BridgeError::InvalidRequest` at the
  shared orchestrator boundary.

### Completed Material Improvement

Extended the orchestrator-owned capability-reference validation so supplied
`CrossProtocolCapabilityRef` values must match the active bridge source
protocol as well as the capability id and parent hash, with a focused
regression proving mismatched source-protocol metadata fails before signed
lineage construction.
