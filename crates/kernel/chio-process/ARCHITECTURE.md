# Process runtime architecture

`ProcessRuntime` composes a SQLite process journal with an `Arc<ChioKernel>`.
It is an embedding API above the kernel TCB, intended for framework and daemon
hosts. It owns process lifecycle bookkeeping and does not implement a second
tool dispatcher or replay engine.

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
withhold output after cancellation. Stronger in-flight revocation and worker
termination require the future authenticated worker/scheduler layer.
