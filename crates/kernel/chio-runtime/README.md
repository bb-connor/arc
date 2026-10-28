# chio-runtime

The public runtime admission and orchestration facade provides runtime errors,
stores and admission hooks backed by `chio-runtime-core`.

A host provisions a `SqliteAuthorityStore`, opens a `SqliteRuntimeOrchestrationStore`,
and calls the authority admission store's `install_runtime_source` with the source
ID, runtime ID, mutation fence and trusted time. It constructs a
`RuntimeParticipantAuthorityBindingV1` from the returned qualification ID and
passes that binding to `ChioRuntimeAdmissionHook::new(profile, source, binding)`.
The host installs the hook and durable stores into the kernel before tool execution.

Admission runs inside kernel execution. The source must retain its exact opened
file identity and immutable destination binding. Unsupported schemas, replaced
files and unqualified backends refuse. Memory and JSON stores retain artifact and
trust-floor utilities but cannot grant operation-owned dispatch authority.

The kernel owns destructive lease and continuation claims. The source stores
bundles, treaty evidence and atomic trust-floor transitions. Swarm admission also
requires the qualified graph issuer and pinned witness keys.

The runtime harness records the signed kernel receipt as its admission artifact.
Workflow and proof-source records bind `admissionReceiptSha256`. Cross-boundary
treaty reports retain their separate report digests.

See [the source contract](../chio-runtime-core/RUNTIME_SOURCE.md) for physical
identity, lifetime and replacement rules, and [ARCHITECTURE.md](ARCHITECTURE.md)
for the facade boundary.
