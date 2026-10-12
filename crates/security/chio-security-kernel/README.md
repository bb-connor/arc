# chio-security-kernel

Adapters that connect Chio's active-defense authorities to the kernel's guard,
pre-dispatch, post-invocation, and capability-issuance interfaces. The crate
reads authoritative security context and delegates state operations to typed
ports. The control plane installs these adapters through `ActiveDefenseRuntime`.

## Usage

Construct a flow output hook with a caller-supplied authority. This offline
example demonstrates that a synthetic output context lacks the trusted context
required by `MissingContextPolicy::Deny`.

```rust
use std::sync::Arc;
use chio_flow::FlowDenial;
use chio_kernel::{PostInvocationContext, PostInvocationHook, PostInvocationVerdict};
use chio_security_kernel::{
    FlowPostInvocationHook, FlowPostInvocationInput, FlowPostInvocationPort,
    MissingContextPolicy,
};

struct RejectFlow;
impl FlowPostInvocationPort for RejectFlow {
    fn evaluate(&self, _input: &FlowPostInvocationInput<'_>) -> Result<(), FlowDenial> {
        Err(FlowDenial::PolicyFlowViolation)
    }
}

let hook = FlowPostInvocationHook::new(Arc::new(RejectFlow), MissingContextPolicy::Deny);
let inspection = hook.inspect_with_evidence(
    &PostInvocationContext::synthetic("read"),
    &serde_json::json!({"result": "sample"}),
);
assert!(matches!(inspection.verdict, PostInvocationVerdict::Block(_)));
assert_eq!(inspection.evidence.len(), 1);
```

The crate declares no Cargo features. It requires the standard library and
enables `std` on `chio-flow` and `chio-security-types`.

## Guarantees

- `FlowPreInvocationGuard` and `FlowPostInvocationHook` convert authority
  failures into deny/block decisions with evidence. Their missing-context
  behavior follows the configured `MissingContextPolicy`.
- `TripwireGuard` bounds argument candidate collection before detector access;
  detector errors and matches deny the invocation.
- `EgressRestrictionGuard` binds the decision to the authoritative tenant and
  session and the request's server ID used as its destination identifier.
- `SessionThrottleGuard` requires a kernel-owned invocation attempt, validates
  the consumed windows against the loaded snapshot, and denies clock failures.
- `IssuanceFreezeAdmission::evaluate()` validates the issuance parent shape and
  returned decision; `authorize()` rejects an active freeze.
- `FlowPreDispatchHook` maps outcome-persistence failure to
  `SecurityDispatchOutcomeRecoveryRequired`.

## Status

Implemented adapters with direct guard tests and kernel integration tests.
`ActiveDefenseRuntime` installs these hooks with missing-context denial and
enforced pre-dispatch policy. Library constructors permit other configurations;
the host must supply trusted context, state authorities, and receipt/event
persistence. Enabling the runtime remains a deployment decision.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Portable security contracts](../chio-security-types/README.md)
- [Control-plane assembly](../../platform/chio-control-plane/src/security.rs)

License: [Apache-2.0](../../../LICENSE).
