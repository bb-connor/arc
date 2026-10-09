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

Snapshots and old journals remain immutable and directly addressable. Archive validation at store open rechecks their canonical bytes, snapshots and global references. Normal checkpoint readers use indexed latest heads and the bounded suffix. Retained storage continues to grow; this lifecycle is not disk erasure. The existing 65,536-current-row and 64-MiB current-row limits remain separate capacity boundaries, and checkpointing never raises them.

## Finished current rows

Each native invocation adds a flow-join transition row for its input join, nonce preflight and output join, and an egress fence row when it acquires egress. Inside the checkpoint transaction, after current rows are authenticated and before the snapshot is copied, the checkpoint deletes the rows that no later native command can read:

- a `flow_join` transition whose identifier the immutable join, output or nonce-preflight journal retains;
- a natively acquired egress fence that is committed, or still pending at or after its expiry under the owner clock.

Every native writer refuses an identifier that is current or retained by any of those journals, using point lookups on their unique indexes, so compaction never reopens an identifier to another operation or family. Recorded retries still return their journal history. A dedicated, checkpoint-only owner performs the deletes: the native triggers accept only planned before-images of this authority from those two tables, each exactly once, and every exit restores the denying callbacks. The deletes, snapshot, checkpoint record and global commit share one transaction, so an interrupted checkpoint leaves the previous rows and anchor intact.

Imported rows, pending unexpired fences, flow labels, contexts, memberships, isolation epochs and declassification state are never compacted. The current-row limit therefore bounds live state plus the dead rows created since the last checkpoint. The automatic maintenance that trusted hosts run before each evaluation seals every 20 suffix events. It also seals whenever dead rows exist and one more native event could exceed the current-row limit, which covers fences that expire without any new event. Explicit maintenance does the same whenever any dead row exists. Two kinds of retained state still grow with distinct use rather than per call: flow state for each distinct principal, lineage, session and isolation epoch, and native declassification use, evidence and outbox rows. They remain under the limit and are refused fail-closed when it is reached.

Before commit, a failed checkpoint transaction leaves the prior projection and anchor intact. An uncertain commit or anchor synchronization poisons the current owner and requires authenticated reopen. Reopen accepts a complete prior or committed checkpoint through the existing anchor-extension proof; missing, corrupted or substituted history refuses service. Restore a coherent, independently authorized store and anchor when necessary. Deleting a journal, changing a schema marker, raising a cap, or restarting from empty native state cannot repair an integrity refusal.

Qualification evidence remains separate: lowered test-only cap recovery, corruption, wrong fence/clock, transaction rollback, process abort, pending custody and reopen must pass on one frozen source before this component is accepted. Whole-candidate native/hosted and operator acceptance are root-owned gates.

The `PostAdmissionDropGuard` model abstracts the live resource ledger. Its source anchors detect implementation drift in checkpoint compaction and identifier occupancy; they do not prove SQLite deletion authorization, archive retention, checkpoint atomicity or recovery. Those boundaries require the owning regression and process-recovery evidence described above. Compaction changes no resource disposition in that abstraction.
