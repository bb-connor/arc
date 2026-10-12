# chio-cross-protocol

Shares capability references, route evidence, lifecycle contracts, and kernel-bound
orchestration across Chio protocol edges.

## Usage

```rust
use chio_cross_protocol::discovery::{DiscoveryProtocol, TargetProtocolRegistry};

let registry = TargetProtocolRegistry::new(DiscoveryProtocol::Native);
assert!(registry.supports_target_protocol(DiscoveryProtocol::Native));
assert_eq!(registry.default_target_protocol(), DiscoveryProtocol::Native);
```

The registry example is offline. Execution additionally needs a live kernel,
a verified manifest registry, authenticated host context when applicable,
and an executor registered for each projected target protocol.

## Guarantees

- `CrossProtocolOrchestrator::execute` validates request and capability-reference
  bindings before preparing a hop.
- `evaluate_bound_kernel_request` repeats boundary validation and preserves
  authenticated session and manifest security context during kernel evaluation.
- `kernel_tool_call_request` retains approval sets and supplemental authorization
  when projecting the execution request.

## Status

Implemented shared orchestration substrate. Protocol-specific execution depends
on registered executors. Route and capability-envelope structures carry evidence;
their serialized values do not independently grant execution authority.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-tool-call-fabric](../chio-tool-call-fabric/README.md)

## License

[Workspace license](../../../LICENSE).
