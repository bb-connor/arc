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

`ProcessRegistry` shares the qualified process store without retaining a
kernel `Arc`. Native lifecycle services can be owned by the kernel without a
kernel-to-runtime reference cycle. The registry resolves the kernel-selected
invocation capability ID, exact canonical capability hash and subject to one
live process. Ambiguous capability reuse rejects. Guest arguments never select
the parent. This remains a trusted embedding API; guests use normal admission.

The opt-in native runner retains subject signing seeds for initial processes
in a private table. Child submission uses an immediate transaction to commit
the attenuated capability, subject seed, immutable task/template and stable
kernel request identity together. Existing attachment validation enforces
lineage, sibling shares, count, depth and cancellation. Failed inserts roll
back all parts. Duplicate submissions retain one identity, and conflicting
input rejects. Committed work remains discoverable after host death even when
the kernel's corresponding outcome is unknown; discovery does not repair or
redispatch that kernel operation. The host controls executable templates.

Direct-child wait records commit after validation of the proposed dependency
graph. The native runner combines them with its declared dependencies and
uses its existing lifetime attempt journal for cooperative resumptions. The
process store owns work identity and parentage; `runner.db` owns OS attempts.
See the [adaptive runner contract](../../products/chio-cli/PROCESS_RUNNER.md#adaptive-child-work).

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

## Durable mailbox tools

The optional native `MailboxServer` registers `send_<channel>`,
`receive_<channel>` and `ack_<channel>` on `chio-ipc`. Each route uses ordinary
kernel capability grants and invocation recovery. Channels authorize endpoint
operations, not claimed sender identities. The server implements the existing
`ToolServerConnection` host interface, with no new worker administrative method.

Its private SQLite database binds the qualified authority, kernel key and
immutable channel configuration. Immediate write transactions serialize queue
capacity, channel-wide message-key deduplication and acknowledgement. Reads
take non-consuming snapshots. Acknowledgement frees payload capacity while
bounded lifetime tombstones prevent identity reuse. Kernel journal replay can
still return a previous receive payload. Mailbox and kernel outcome commits
are separate; uncertain outcomes remain blocked. See [MAILBOXES.md](MAILBOXES.md)
for polling, retention, guard transformation and acknowledgement semantics.

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

`examples/langgraph_report.rs` runs an identical report graph with native
LangGraph tools and the authenticated process adapter. Real Python workers
exit after publication returns but before the graph node checkpoint. The
host checks duplicate publication counts, recovered receipt identity, pinned
receipt signatures and read-only authority enforcement. Both backends use
persistent LangGraph SQLite checkpoints with synchronous durability.

`tests/mailboxes.rs` checks endpoint authority through the kernel, original
receipt replay after acknowledgement and restart, fresh versus repeated polls,
canonical payload byte limits, count and lifetime quotas, concurrent writers,
message-key conflicts, cancellation and configuration/authority replacement.

`tests/child_submission.rs` checks atomic child/key/work rollback, immutable
submission identity, separate-connection duplicate and cancellation races,
and host death after child commit but before the kernel records an outcome.

These are behavioral tests. They do not qualify a scheduler, worker OS
isolation, a public network deployment, or distributed migration.
