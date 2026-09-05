# Process runtime architecture

`ProcessRuntime` composes a SQLite process journal with an `Arc<ChioKernel>`.
It is an embedding API above the kernel TCB, intended for framework and daemon
hosts. It owns process lifecycle bookkeeping and does not implement a second
tool dispatcher or replay engine.

## Persistent identity and lifecycle

The journal uses WAL, synchronous FULL, foreign keys and immediate write
transactions. It stores an immutable authority UUID, signing key and random
runtime namespace. All request ids derive from canonical JSON of that
namespace, the process id and an operation key. Length and control-character
checks bound identifiers, while tuple encoding prevents concatenation
collisions. Absolute file paths prevent SQLite URI or `:memory:` semantics.

Root registration and child attachment reject conflicting identity reuse.
Process ids are never recycled. Child insertion and cancellation serialize on
the same SQLite write transaction, so a child cannot escape its parent's
cancelled subtree. Parentage only points to existing processes and cannot be
changed; depth is capped at 64. Root-local process counts include cancelled
children so repeated creation and cancellation cannot bypass the limit.
Sibling budget shares are allocated in the child insertion transaction and
remain allocated after cancellation. Each parent-to-child edge is covered,
including intermediate parents that never execute a tool call.

## Kernel authority and recovery

Before invocation, the runtime restores the persisted lineage root-first via
`ChioKernel::register_delegation_parent`. That method uses the existing
non-tool capability validation path, including trust, validity and revocation,
records the verified ancestor snapshot, and registers its signed budget share.
It does not consume tool invocation budgets. Host-supplied trust roots remain
in kernel configuration; process registration cannot install one.
For narrowed multi-hop chains, the kernel loads the original signed ancestor
tokens and passes them to the shared pure verifier. Each exact chain prefix,
scope transition, signature, validity interval and budget share is checked.
The legacy path still rejects such chains without signed intermediate evidence.

The call admission transaction checks process state and exact capability and
subject binding, freezes the complete canonical request hash, and increments
the root's shared counter for new logical operations. It commits before
calling the kernel and holds no journal lock across the async dispatch. A
failure after this commit retains the reservation. Retrying the same operation
uses the same request id and authority, including after an OS process exits.

The kernel remains authoritative for dispatch commitment, tool return,
guard evaluation, payment, receipt persistence and terminal replay. No
process journal transition authorizes redispatch of an ambiguous effect.
The runtime does not interpret tool failures as proof that no effect occurred.

Checkpoints use compare-and-swap revisions. They are application state and
are not atomically committed with external tool effects. Applications may
repeat a logical call after recovering an older checkpoint: the kernel
recovers that operation without blindly repeating the effect.

Cancellation changes admission state permanently. It does not fence a call
already admitted by the process journal. A completion checks state again to
withhold output after cancellation. Worker OS termination requires a separate
host lifecycle or scheduler implementation.

## Authenticated worker boundary

The optional worker service derives process identity from a random bearer
credential whose digest, expiration and binding persist in the same journal.
The guest request type has no capability, process selector or administrative
operation. All tool requests are reconstructed with the persisted capability
and sent through `ProcessRuntime::invoke`. Revocation and expiry are checked
again before returning output; already admitted effects may finish.

The Unix listener bounds frames, active connections and transport deadlines.
It retains an admitted kernel future after client disconnect, and graceful
shutdown drains active requests. This preserves durable admission's recovery
semantics across delivery failures. Worker OS isolation and secret delivery
remain host responsibilities. Signed receipts remain JSON text in both SDKs
so JavaScript parsing cannot round signed integer fields.

## Verification focus

`tests/processes.rs` exercises child and grandchild scope enforcement, immutable
identity, shared call ceilings across separate database connections, dormant
parent share allocation, checkpoint conflicts and cancellation during dispatch.
`tests/crash_recovery.rs` exits real OS processes after a committed result and
after an external effect whose outcome has not been recorded. It verifies
original receipt replay and fail-closed uncertain-outcome recovery respectively.
The example exercises eight logical workers across a coordinator crash.

`tests/worker_protocol.rs` exercises authentication, guest operation boundaries,
credential revocation and expiry, bounded framing, output-size failure and
disconnected clients. `tests/polyglot_workers.rs` runs Python and Node as real
OS workers, kills their host after publication, then verifies persisted
authentication, original receipt recovery and the shared call ceiling in a
fresh host process.

These are behavioral tests. They do not qualify a scheduler, worker OS
isolation, a public network deployment, or distributed migration.
