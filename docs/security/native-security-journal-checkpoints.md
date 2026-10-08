# Native security journal checkpoints

Native security mutations retain an append-only history of flow joins, egress decisions, output joins and nonce-preflight joins. One authority's active journal segment admits at most 65,536 events and 67,108,864 bytes (64 MiB). Reaching either limit denies the new mutation and rolls its transaction back. The operation and its original native binding remain available for retry.

## Operator limits

| Limit | Value | Scope |
|-------|-------|-------|
| Active journal segment | 65,536 events or 67,108,864 bytes (64 MiB), whichever is reached first | One security authority, summed across the four journal families, counting only events after the latest checkpoint |
| Current native rows | 65,536 rows | All security authorities in one admission store |
| Native initializations | 16 | One admission store |
| Automatic checkpoint cadence | 20 or more events since the latest checkpoint | One security authority |

The kernel checkpoints automatically. Before each native evaluation it calls `checkpoint_native_security_history_if_due` for the selected authority, which folds the active segment once it holds 20 or more events. A completed native call appends about five events, so under normal operation the active segment holds the suffix of at most four completed calls and stays far below the cap. A segment that approaches the cap means automatic maintenance is not running or is failing, and should be treated as an incident before the cap is reached.

At the cap, every native-security mutation for that authority is denied with:

```text
admission operation invariant failed: native security state: combined native journal exceeds bounds
```

The mutation's transaction rolls back and the operation stays retryable. Recover by running the explicit checkpoint below from the serving host, then retry the denied operation. Raising the cap, deleting journal rows or restarting from empty native state is not a recovery path; see the integrity rules at the end of this page.

Checkpoints fold events but never erase them. Snapshots and folded journals stay on disk, so the admission database grows with native traffic for the lifetime of the store. Size its volume for retained history and alert on free space, not on the journal cap.

## Explicit checkpoint

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

The next journal segment uses the same production cap. Current row verification begins with the latest authenticated snapshot and replays the bounded suffix. Original event sequences and hash chains continue monotonically. Historical operation proofs, pending egress fences, nonce-preflight state and restrictive labels remain under their original authority and initialization. Repeating maintenance without new native events returns the same anchored checkpoint digest.

Snapshots and old journals remain immutable and directly addressable. Archive validation at store open rechecks their canonical bytes, snapshots and global references. Normal checkpoint readers use indexed latest heads and the bounded suffix. Retained storage continues to grow; this lifecycle is not disk erasure. The existing 65,536-current-row and 64-MiB current-row limits remain separate capacity boundaries and checkpointing does not prune transition identities or old claims to bypass them.

Before commit, a failed checkpoint transaction leaves the prior projection and anchor intact. An uncertain commit or anchor synchronization poisons the current owner and requires authenticated reopen. Reopen accepts a complete prior or committed checkpoint through the existing anchor-extension proof; missing, corrupted or substituted history refuses service. Restore a coherent, independently authorized store and anchor when necessary. Deleting a journal, changing a schema marker, raising a cap, or restarting from empty native state cannot repair an integrity refusal.

Qualification evidence remains separate: lowered test-only cap recovery, corruption, wrong fence/clock, transaction rollback, process abort, pending custody and reopen must pass on one frozen source before this component is accepted. Whole-candidate native/hosted and operator acceptance are root-owned gates.
