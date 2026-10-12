# chio-runtime

The public Chio runtime admission and orchestration facade.
It provides runtime-owned errors, stores, and admission hooks while delegating
evaluation to `chio-runtime-core`.
Applications can use this boundary without naming the implementation store traits.

## Usage

Evaluate a request against an empty process-local store to observe closed admission:

```rust
use chio_runtime::{
    evaluate_runtime_admission, ChioRuntimeAdmissionInput, InMemoryRuntimeAdmissionStore,
    RuntimeAdmissionProfile, RuntimeRequestBinding, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
};

let store = InMemoryRuntimeAdmissionStore::new();
let profile = RuntimeAdmissionProfile {
    schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.into(),
    profile_id: "example".into(), local_kernel_id: "kernel-local".into(),
    verifier_id: "verifier-local".into(),
    issued_at_unix_ms: 1_000, expires_at_unix_ms: 3_000,
};
let request = RuntimeRequestBinding {
    request_id: "request-1".into(), capability_id: "capability-1".into(),
    server_id: "tools".into(), tool_name: "read".into(),
    tool_args_sha256: "0".repeat(64), origin_kernel_id: None,
    host_kernel_id: "kernel-local".into(),
};
let report = evaluate_runtime_admission(ChioRuntimeAdmissionInput {
    profile: &profile, store: &store, admission_id: "admission-1", request: &request,
    action_class_id: None, runtime_trust_input: None, trusted_verifier_keys: &[],
    pheromone_query_report: None, runtime_pheromone_policy: None,
    runtime_peer_weights: None, now_unix_ms: 2_000,
})?;
assert!(!report.accepted);
assert_eq!(report.failure_code.as_deref(), Some("missing_admission_bundle"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

The sample uses ordinary dependencies, needs no services, and writes no files.
Admission requires a fresh profile and an exactly bound stored bundle.
Verifier trust input is optional when the trusted-key set is empty; supplying
trusted keys requires matching signed trust input. Selected policies can add requirements.
A kernel host installs `ChioRuntimeAdmissionHook` to mediate actual dispatch.

## Guarantees

- `evaluate_runtime_admission` checks profile freshness and exact stored request binding.
- `ChioRuntimeAdmissionHook` resolves treaty and swarm evidence from its store.
- Trust-floor transitions require atomic validation and recording by the backend.
- Destructive leases and single-use continuations use store reservation operations.
- Operation-owned replay requires an explicitly bound, verified replay source.

## Status

Implemented admission and local orchestration APIs with no declared Cargo features.
Memory stores retain state for one process. JSON stores coordinate clones of one
instance; independent opens require SQLite for serialized transitions.
Memory and JSON backends do not qualify sealed operation-owned replay by default.
Report generation requires caller-supplied evidence and provider observations.
These APIs do not launch an external provider service or certify a deployment.

## Related

- [Architecture](ARCHITECTURE.md)
- [Capability verification](../../../spec/PROTOCOL.md#53-verification-rules)
- [Runtime implementation](../chio-runtime-core/README.md)
- [License](../../../LICENSE)
