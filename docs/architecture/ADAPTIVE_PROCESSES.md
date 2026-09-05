# Adaptive process execution

This design extends the experimental local process host so a running worker
can create narrower child work discovered during execution. The opt-in Linux
profile is implemented in the native process host with Python and Node
integration evidence. It remains an experimental local execution profile.
See the [operator and worker contract](../../crates/products/chio-cli/PROCESS_RUNNER.md#adaptive-child-work)
for configuration, limits and recovery behavior.

## Invocation boundary

Child creation and joins are native kernel tools. They retain ordinary guard,
budget, dispatch, receipt and unknown-outcome behavior. The caller comes from
kernel-selected invocation context and its exact persisted capability, never
a `parent_id` supplied in tool arguments. Context contains identity digests
and a route, not a capability token, signing seed or wire credential.

Operators select spawn templates at initialization: tool routes and maximum
budget shares. A pinned run plan binds those templates to literal executable
commands, working directories, fixed configuration, deadlines and attempt
ceilings. Workers supply task input and a bounded share. They cannot choose
executables, replace policy or mint arbitrary capabilities. The host retains
private subject keys only for the opt-in delegation profile and uses existing
attenuation and signed ancestor validation.

## Durable submission

The process database must atomically commit the child process, its subject key,
the template/task binding and the logical submission identity. Replaying the
same submission cannot allocate another child, reclaim cancelled slots or
reset sibling budget shares. Capacity and cancellation serialize with child
attachment in the same process-store transaction. No cross-database repair
may create a child after a failed submission returned.

The runner discovers committed submissions, resolves their pinned templates
and adds them to its durable attempt journal. Existing completed workers stay
completed. Unknown kernel outcomes retain their existing fail-closed behavior,
even when child creation already committed. Diagnostics remain observations
and do not authorize dispatch.

## Waiting and scheduling

Waiting parents must release their OS worker slot rather than deadlock a
single-slot pool. A guarded join records direct-child dependencies; the worker
checkpoints its continuation and exits with a designated suspension code.
The runner resumes it when dependencies complete, retaining the same process,
checkpoint and tool-operation identities. Launches, including cooperative
resumes, remain bounded by the persistent attempt ceiling. A new completed
join poll uses a new logical key, as with existing mailbox polling.

The combined declared and dynamic dependency graph must reject cycles before
accepting a wait. Dynamic children start without a dependency on their parent's
exit. Child failure and cancellation remain fail-closed under the runner's
existing application failure boundary.

## Evidence

- Kernel caller binding reaches value, monetary, streaming and nested dispatch
  without changing existing connector behavior; denied calls never reach it.
- A real parent discovers and starts children absent from the initial run plan,
  then resumes after joining them with a concurrency ceiling of one.
- Narrowed children and grandchildren cannot acquire their parent's broader
  tool rights, override their parent identity or exceed shared process budgets.
- Parent interruption after submission, host death, cancellation races and
  child retries preserve one child identity and original known tool receipts.
- Changed submissions, unknown templates, dependency cycles and incompatible
  run-plan configuration reject without extra worker execution.
- Private subject keys, capabilities and credentials stay outside worker input,
  diagnostics, model-visible schemas and exported evidence.

`chio-kernel`'s `invocation_context_` tests exercise caller binding and connector
compatibility across dispatch modes. `chio-process/tests/child_submission.rs`
checks atomic rollback, concurrent duplicate submission, cancellation races
and a host killed after child commit before kernel outcome persistence.
`chio-cli/tests/process_host/adaptive.py` runs one Python root, a Python branch
and three Node leaves at concurrency one, including two grandchildren. It
verifies original spawn/send receipts against the initialization key after
worker and host death, plus dependency cycles, quota/count bounds, scope
narrowing, forged arguments and template drift. These are execution fixtures,
not evidence of model reasoning quality or external adoption.
