# chio-runtime architecture

The facade owns runtime errors, store wrappers and `ChioRuntimeAdmissionHook`.
Artifact types and verification delegate to `chio-runtime-core`; native tool
execution and signed receipts belong to the kernel.

`lib.rs` exports artifact types, schema constants, parsers and report functions.
`stores.rs` adapts artifact reads and atomic trust-floor operations.
`stores/source_qualification.rs` forwards physical SQLite source qualification.
`admission_hook.rs` requires a participant binding at construction and forwards
operation-owned admission and dispatch revalidation to the core hook.

The destination authority installs the source under its serving fence. The hook
verifies that same physical source before using an operation-owned claim. There
is no standalone admission evaluator or source activation/import path. The kernel
retains claim and release custody; source stores do not consume continuations or
reserve destructive leases independently.

Swarm evidence comes from the qualified graph issuer and pinned witness keys.
Canonical hashing, signature verification and bounded decoding use the core
implementation. A hook or open database alone grants no tool capability.

Runtime workflow evidence binds the actual signed kernel admission receipt.
Treaty cross-boundary reports remain separately verified artifacts. Both use v1
contracts; retired field names have no aliases.

`tests/runtime_boundary/source_qualification.rs` covers the facade/core physical
source boundary. `tests/reserved_caller.rs` covers authenticated reserved caller
access. Core integration tests cover source schema, identity and destination
installation refusals. Executed qualification is recorded separately for each
candidate SHA.
