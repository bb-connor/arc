# Native security journal checkpoints

Native security mutations retain an append-only history of flow joins, egress decisions, output joins and nonce-preflight joins. One authority's active journal segment admits at most 65,536 events and 67,108,864 bytes (64 MiB). Reaching either limit denies the new mutation and rolls its transaction back. The operation and its original native binding remain available for retry.

Admission schema 36 adds `SqliteAdmissionOperationStore::checkpoint_security_participant_history`. Invoke this explicit maintenance method from the already serving, trusted host using its selected initialization and current serving fence. It can run before the segment reaches capacity, or after a cap denial has rolled back. Retry the same denied operation afterward under its actual current recovery lease.

```rust
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationStoreError,
};
use chio_store_sqlite::SqliteAuthorityStore;

fn checkpoint_native_journal(
    authority: &SqliteAuthorityStore,
    selected_authority: &AdmissionIdentifier,
    host_now_unix_ms: u64,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    let fence = authority.mutation_fence();
    let store = authority.admission_operation_store();
    let initialized = store
        .load_security_participant_state(selected_authority, &fence, host_now_unix_ms)?
        .ok_or_else(|| AdmissionOperationStoreError::Invariant(
            "selected native initialization is absent".into(),
        ))?;
    store.checkpoint_security_participant_history(
        &initialized, &fence, host_now_unix_ms,
    )
}
```

`selected_authority` comes from the host's authenticated deployment selection. The supplied host timestamp undergoes the ordinary skew check; the store independently observes its owner clock and enforces the durable native clock floor. Neither parameter is an invocation credential.

The checkpoint seals exact current canonical rows, four family heads and digests, the original initialization, the previous checkpoint, current serving ownership and the previous global commit anchor. It shares one IMMEDIATE SQLite transaction and one global commit with its retained snapshot. The existing protected rollback anchor authenticates the checkpoint's exact global reference. Its local digest alone cannot authorize a fold boundary, and the checkpoint does not introduce a new signing key or signed public artifact.

The next journal segment uses the same production cap. Current row verification begins with the latest authenticated snapshot and replays the bounded suffix. Original event sequences and hash chains continue monotonically. Historical operation proofs, pending egress fences, nonce-preflight state and restrictive labels remain under their original authority and initialization. Repeating maintenance without new native events or newly dead rows returns the same anchored checkpoint digest.

Snapshots and old journals remain immutable and directly addressable. Archive validation at store open rechecks their canonical bytes, snapshots and global references. Normal checkpoint readers use indexed latest heads and the bounded suffix. Retained storage continues to grow; this lifecycle is not disk erasure. The store-wide 65,536-current-row ceiling and the per-authority 64-MiB current-byte ceiling remain separate capacity boundaries, and checkpointing never raises them.

## Finished current rows

Each native invocation adds a flow-join transition row for its input join, nonce preflight and output join, and an egress fence row when it acquires egress. Inside the checkpoint transaction, after current rows are authenticated and before the snapshot is copied, the checkpoint deletes the rows that no later native command can read:

- a `flow_join` transition whose identifier the immutable join, output or nonce-preflight journal retains;
- a natively acquired egress fence that is committed, or still pending at or after its expiry under the owner clock;
- a complete native session whose restrictions are already carried by its principal, provided no egress fence or unfinished operation retains that session. Its label, membership and every lineage context leave together.

Every native writer refuses an identifier that is current or retained by any of those journals, using point lookups on their unique indexes, so compaction never reopens an identifier to another operation or family. Recorded retries still return their journal history. A dedicated, checkpoint-only owner performs the deletes: the native triggers accept only planned before-images of this authority from the transition, egress-fence, session-label, membership and context tables, each exactly once, and every exit restores the denying callbacks. The deletes, snapshot, checkpoint record and global commit share one transaction, so an interrupted checkpoint leaves the previous rows and anchor intact.

Imported rows, principal and lineage labels, isolation epochs, sequences and declassification state are never compacted. A session with restrictions its principal does not carry also stays current. Session retirement scans at most 1,024 unfinished operations; exceeding that bound or finding incomplete context evidence retains every session. Reusing a retired session identifier inherits the retained principal and lineage restrictions and receives a fresh context generation; it cannot restart at an unrestricted label. The current-row limit therefore bounds live state plus the dead rows created since the last checkpoint. The automatic maintenance that trusted hosts run before each evaluation seals every 20 suffix events. It also seals whenever dead rows exist and one more native event could exceed the current-row limit, which covers fences that expire without any new event. Explicit maintenance does the same whenever any dead row exists. Two kinds of retained state still grow with distinct use rather than per call: flow state for each distinct principal, lineage, non-dominated session and isolation epoch, and native declassification use, evidence and outbox rows. They remain under the limit and are refused fail-closed when it is reached.

Before commit, a failed checkpoint transaction leaves the prior projection and anchor intact. An uncertain commit or anchor synchronization poisons the current owner and requires authenticated reopen. Reopen accepts a complete prior or committed checkpoint through the existing anchor-extension proof; missing, corrupted or substituted history refuses service. Restore a coherent, independently authorized store and anchor when necessary. Deleting a journal, changing a schema marker, raising a cap, or restarting from empty native state cannot repair an integrity refusal.

Qualification evidence remains separate: lowered test-only cap recovery, corruption, wrong fence/clock, transaction rollback, process abort, pending custody and reopen must pass on one frozen source before this component is accepted. Whole-candidate native/hosted and operator acceptance are root-owned gates.

The `PostAdmissionDropGuard` model abstracts the live resource ledger. Its source anchors detect implementation drift in checkpoint compaction and identifier occupancy; they do not prove SQLite deletion authorization, archive retention, checkpoint atomicity or recovery. Those boundaries require the owning regression and process-recovery evidence described above. Compaction changes no resource disposition in that abstraction.

## Admission headroom and remaining capacity

The current-row ceiling is **65,536 rows across the store**. It counts all native
current tables, including declassification use, evidence and outbox rows. It is
separate from both the journal segment limits and the **64 MiB current-byte limit
per authority**. Checkpointing cannot reclaim authoritative principal or lineage
state simply to make room.

New native admission uses three row controls within its transaction:

- Each unfinished operation with a first native write reserves eight additional
  rows. This covers its possible dispatch transition, egress fence, three
  declassification commitment rows and three output rows. A nonce preflight and
  its later dispatch share one reservation. Parked approval operations retain
  their reservation until terminal. The reservation scan refuses incomplete
  evidence at 65,537 unfinished operations.
- A write opening a new flow identity leaves another 4,096 rows for operations
  on existing identities. An existing-identity write does not consume this
  floor merely because it is a new operation.
- A write opening a new identity must fit its principal's share of 8,192
  attributed rows under `(authority, tenant, principal)`. Principal labels,
  session labels, memberships and contexts each count once; an isolation epoch
  counts twice to account for its possible lineage label. Declassification rows
  use the global budget and are not attributed to this share.

Let `R` be the current rows after the proposed first write and `N` the unfinished
operations that already have native history before it. Admission requires
`R + 8 * (N + 1) + F <= 65,536`, where `F` is 4,096 when the write opens an
identity, otherwise zero. Trusted hydration requires `R + 8 * N + 4,096 <= 65,536`. It preserves imported authority without imposing the
per-principal share on that historical state; the next identity-opening native
write must meet the share. This does not promise imported principals are already
below 8,192 rows.

Unfinished work also has a concurrency ceiling. With current and proposed rows
included in `R`, reservation headroom permits at most
`floor((65,536 - R - F) / 8)` unfinished operations. Roughly 8K at an empty store
is an algebraic upper bound; actual native state and in-flight rows reduce it.
Long-parked approvals and operations stuck in capture retain reservations until
terminal state. The principal identity share does not cap existing-identity
concurrency or unattributed declassification, so it does not guarantee isolation
of every principal's reservation headroom.

A refused admission rolls back and returns
`AdmissionOperationStoreError::Unavailable` with the prefix
`native security current-row capacity is exhausted:`. Its detail identifies
principal sharing, the global row/reservation/floor calculation, or an incomplete
unfinished-operation scan. This resource refusal can be retried after legitimate
completion or checkpoint maintenance frees capacity. Retry alone cannot reclaim
permanent authority.

The limits below describe settled row growth, not exact admission counts.
The first four identity counts were measured after two checkpoints; the five
declassification rows are derived from the closed mutation change sets:

| Retained class | Current rows retained per distinct use |
| --- | --- |
| Lineage root with its isolation epoch | 2 |
| Principal with its retained principal/lineage/epoch authority | 3 |
| Session whose taint is not dominated by its principal | 3 (label, membership, context) |
| Completed native declassification | 5 (use, two evidence rows, two outbox rows) |
| Tenant flow sequence | 1 |

After the identity floor and the new operation reservation, the upper bound
on `R` is `61,432 - 8 * N`. With no other rows or unfinished operations, two rows
per lineage give at most 30,716 settled roots store-wide, before transient
admission costs; one principal reaches its share earlier. These are algebraic
upper bounds, not measured production admission counts. The principal share,
other retained classes, transient rows and reservations can refuse a workload
earlier. Session retirement bounds
eligible session churn, not unrestricted growth in distinct principals,
lineages, non-dominated sessions or declassification authority.

The lowered fixtures make these distinctions observable without treating their
budgets as production limits. At the B3 predecessor, a 327-row fixture refuses
`302 + 8 + 20 > 327`; at the B2 predecessor, a 336-row fixture refuses
`163 + 176 > 336` while reserving completion for 22 operations. At the final B4
share, a 327-row fixture allows 12 session-only-tainted sessions for one
principal, then refuses the thirteenth at 42 attributed rows against a share of
40 while a second principal can still admit. The earlier controls deliberately
rotate principals in the final suite so the share cannot mask a global-budget
failure. Source-bound Original and final results remain in the qualification
audit; these are boundary fixtures, not throughput measurements.

The reservation covers **rows only**. It does not reserve encoded bytes or disk
space. The separate current-byte cap can still refuse later work with an
`Invariant` error, and lasting state can permanently fill that budget.
**SEC-1160-COLDSTATE remains OPEN P1**, including authenticated cold state,
byte-capacity recovery and the durable authority classes that cannot be deleted.
Under owner decision 0020 this blocks G5 outside-team preview, while the bounded
foundation may land after its remaining qualification gates. No production or
unlimited-capacity claim follows from this repair.
