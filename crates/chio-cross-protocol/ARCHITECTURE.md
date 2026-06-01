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

## Planned Material Improvement

Add an orchestrator-owned execution boundary validation step before capability
reference injection, route planning, trace construction, or kernel execution.
Require non-empty request identity fields and verify any supplied
`CrossProtocolCapabilityRef` against both the active capability id and the
deterministic parent capability hash. This turns lineage data from trusted
caller metadata into a checked shared invariant.
