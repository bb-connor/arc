# chio-cross-protocol architecture

## Responsibility and boundary

Shares capability references, route evidence, lifecycle contracts, and kernel-bound
orchestration across Chio protocol edges.

Implemented shared orchestration substrate. Protocol-specific execution depends
on registered executors. Route and capability-envelope structures carry evidence;
their serialized values do not independently grant execution authority.

## Structure

`capability_bridge` defines references, envelopes, and trace types.

`discovery` owns protocol names and the target executor registry.

`routing` plans routes and constructs selection evidence.

`orchestrator` prepares, projects, executes, and records bridged hops.

`execution` projects kernel requests and includes `OpenAiTargetExecutor`.

`lifecycle` and `semantic_hints` share edge lifecycle and discovery vocabulary.

Private `validation` checks identity, approval, session, and registry bindings.

## Data and control flow

A source `CapabilityBridge` extracts protocol context and an optional
capability reference. The orchestrator matches that reference to the active
capability ID, source protocol, and canonical parent-capability hash.

Route planning considers registered executors, availability, and governed
intent hints. A selected hop is projected for its target executor.

Native evaluation uses the kernel directly. Registered target executors
receive the kernel, verified registry, peer profile, and prepared request.
The result collects receipts, protocol output, route hops, and trace context.

## Trust and invariants

`validate_execution_request_boundary` checks nonempty unpadded identities,
session/security-context correspondence, approval-set shape, and admitted
manifest argument bindings. Threshold sets are limited to 32 tokens.

`evaluate_bound_kernel_request` validates negotiated peer capabilities and
chooses a kernel entry point that retains authoritative host context.
Kernel capability and signature validation occurs at that entry point.

Capability envelopes and `RouteSelectionEvidence` have no standalone signature
field or verifier here. Canonical hashes bind lineage; signed kernel receipt
metadata can carry route evidence. Consumers must verify the receipt and
its trust root before treating that evidence as authenticated.

## Dependencies

`chio-kernel` supplies evaluation and receipt responses. `chio-manifest`
supplies verified registry security bindings. Core types provide capability,
governance, canonical JSON, and hashing. Tokio and futures support lifecycle work.

## Verification

`src/tests.rs` exercises orchestration, projected requests, routing, manifest
bindings, and invalid authority context. Tests use supplied kernels and
executors; deployed protocol connectivity depends on the host integration.

Run the focused crate suite from the workspace root:

```bash
cargo test -p chio-cross-protocol
```

See the [README](README.md) for a minimal public API example and requirements.
