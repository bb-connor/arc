# chio-process

Durable, capability-bound agent processes over `chio-kernel`. A host can give
each worker a persistent identity, delegate a narrower capability to children,
checkpoint progress, and recover logical tool calls after a crash.

```bash
cargo run -p chio-process --example recoverable_swarm
```

The example runs eight logical workers against a local file-writing tool.
Four workers finish, then the coordinator exits before its checkpoint. A fresh
OS process repeats their logical calls and starts the remaining four workers.
It verifies the original signed receipts replay unchanged and the external log
contains exactly eight effects across twelve invocation attempts. This is a
deterministic runtime demonstration with disposable test credentials; it does
not launch LLM agents or access external accounts.

## Host API

| Operation | Behavior |
| --- | --- |
| `ProcessRuntime::open(path, kernel)` | Requires durable admission for all calls and a qualified authority store. Persists and checks the authority UUID and kernel signing key across opens. |
| `create_root(id, capability, limits)` | Registers an immutable root capability and tree-wide process, depth, and logical-call ceilings. Repeating the same registration is idempotent. |
| `spawn(parent, child, capability)` | Requires one signed delegation hop from this exact parent, the same issuer and budget family, and narrower scope, validity and budget share. |
| `tool_request(process, key, server, tool, args)` | Builds a request using the persisted capability and a stable request id scoped to the runtime, process and logical operation key. |
| `invoke(process, key, request)` | Freezes the request binding, reserves one shared call slot, then invokes or recovers through the existing kernel admission coordinator. |
| `checkpoint(process, revision, value)` | Saves up to one MiB of JSON with compare-and-swap revision checking. |
| `process(id)` | Reads identity, parentage, state, checkpoint and the shared call count. |
| `cancel(id)` | Permanently stops new admissions and checkpoints for a process and its descendants. |

Hosts construct and configure the kernel with durable receipt, revocation,
budget, admission and outcome stores, and install its capability trust roots.
The runtime restores verified ancestor snapshots and budget-parent registrations
before invoking a leaf. Parents do not need to execute a dummy tool call to
make their children runnable. Capability minting uses the existing authority
and delegation APIs; this crate does not introduce another issuer.

Logical operation keys name effects, such as `publish-report`, and stay the
same after recovery. A changed request under an existing key is a conflict,
including changed authorization extensions. Hosts attach DPoP and governed
authorization to the constructed request before `invoke`; refreshing those
artifacts does not implicitly create a new attempt.

## Recovery and boundaries

The process database records identity, checkpoints, immutable request hashes
and call reservations. Tool output, signed receipts, dispatch fencing and
uncertain-outcome recovery remain in Chio's existing durable authority.
Every invocation traverses the kernel; there is no process output cache.

A completed operation can replay its original receipt and output. If the host
dies after an external effect but before recording the outcome, recovery
denies another dispatch and preserves the kernel's unknown-outcome state.
This prevents blind retry; it is not an exactly-once guarantee for an arbitrary
external service. Recovery still requires valid, unrevoked lineage and the
kernel's current admission rules.

One logical call consumes one tree slot, including denied or uncertain calls.
Repeating that same call does not consume another slot. This host ceiling is
separate from the kernel's monetary, invocation and sibling-share budgets.
Sibling shares must fit their parent even when the tree call ceiling has room.
The journal reserves those shares when children are attached, so parents that
only spawn grandchildren are covered. Cancelled children retain their shares;
automatic budget reclamation is not implemented.

Cancellation linearizes against the process journal's admission transaction.
Previously admitted calls may complete their effects. The runtime withholds
their output if cancellation has been recorded before its return check. It
does not kill an OS process, revoke a capability outside this runtime, undo a
tool effect, or delete dispatch history.

The core API is for trusted hosts. The optional `worker-server` feature adds
an authenticated Unix socket service with Python and JavaScript clients.
It binds each bearer credential to exactly one process and exposes invoke,
inspect, checkpoint and subtree cancellation. Workers must not have direct
access to the runtime, database, kernel administration, or tool credentials.
Use a private directory (0700 on Unix); the process database is created as
0600. It contains capabilities and application checkpoint data.

The present surface does not provide a scheduler, worker leases, worker-to-worker
IPC, framework-specific adapters, OS isolation, or distributed process migration.
Those are the next parts of the [agent process direction](../../../docs/architecture/AGENT_PROCESS_DIRECTION.md).

For the worker contract and an actual Python/Node host-crash demonstration, see
[WORKER_PROTOCOL.md](WORKER_PROTOCOL.md):

```bash
cargo run -p chio-process --features worker-server --example polyglot_swarm
```

The [LangGraph adapter](../../../sdks/python/chio-langgraph/README.md) keeps an
existing graph's planning and checkpoints while its tool node dispatches
through this runtime. `langgraph_report` compares the same report graph with
native tools and Chio under worker death between publication and checkpoint:

```bash
uv sync --project sdks/python/chio-langgraph --locked --extra dev --extra process
cargo run -p chio-process --features worker-server --example langgraph_report
```

## Validation

```bash
cargo test -p chio-process
cargo test -p chio-process --features worker-server
cargo clippy -p chio-process --all-targets -- -D warnings
```

`tests/crash_recovery.rs` starts real OS processes and exits without running
Rust destructors at two boundaries: after a committed result, and inside the
tool after a durable external effect. The parent verifies the external effect
count and recovery result. Other tests exercise scope enforcement, exact
request binding, shared limits across separate SQLite connections, checkpoint
conflicts, cancellation and authority replacement.
