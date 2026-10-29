# chio-runtime-core

Chio runtime admission, verifier trust floors, orchestration state, and local operations reports. The kernel admission hook binds verified evidence to a concrete tool request and its durable operation.

## Configuration

Provision a destination `SqliteAuthorityStore` and open a fresh `SqliteRuntimeOrchestrationStore`. The destination's admission store installs the configured backend with `install_runtime_source`. Retain its qualification ID in `RuntimeParticipantAuthorityBindingV1`, then pass that binding to `ChioRuntimeAdmissionHook::new` with the profile and backend.

The kernel supplies operation-owned claim authority. A source descriptor, historical report, or direct call to the hook's generic evaluation method cannot substitute for that authority. Admission checks profile freshness, exact stored request binding, verifier trust, and selected policies. Treaty and swarm references require their configured verifiers and issuers.

Destructive leases and single-use continuations belong to the destination's operation-owned resource claims. Artifact and trust-floor backends expose no independent consume or release API. Trust-floor updates require atomic validation and recording.

## Source lifetime

A qualified SQLite source is bound to its opened file's device, inode and single-link identity. A copy, restore, replacement, or remount that changes that identity refuses with `runtime_source_qualification_invalid`. Fenced operator requalification supersedes an exact prior record and installs independently provisioned new source and runtime IDs. Prior bindings and claim history are retained; only the new source may authorize fresh work. The destination limits are 128 active sources, 1,024 retained supersessions and 1,152 retained qualifications. Counts are checked before decoding stored history. At the supersession limit, a new replacement refuses before source callbacks; an identical retry still verifies its retained replacement. See [Runtime source qualification](RUNTIME_SOURCE.md).

Memory stores retain artifacts and trust floors for one process. JSON stores coordinate clones of one instance; independent opens require SQLite for serialized transitions. Memory and JSON stores do not qualify operation-owned runtime sources. Report generation consumes supplied evidence and observations.

## Related

- [Architecture](ARCHITECTURE.md)
- [Runtime source qualification](RUNTIME_SOURCE.md)
- [Public runtime facade](../chio-runtime/README.md)
