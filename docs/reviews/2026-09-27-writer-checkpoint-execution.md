# Writer accounting and typed checkpoint continuation

This batch continues Correction 3A and Packet 3 from `916e5d8364` in the existing
`packet/3-retention-accounting` worktree. It also implements the checkpoint
single-parser work in Packet 10.4. Work and review ran inline, with no subagents.

## Writer ownership and arithmetic

Each queued command now owns its checked queue and inflight reservations.
Write commands also own one accepted outcome. Rejection cancels only that
command's reservations; dequeue releases only its queue slot; completion or
unwind records exactly one terminal outcome and releases its inflight slot.
Maintenance commands own inflight reservations without inflating write totals.
Control commands own queue slots. The sender and actor share one health object.

Append batches finish their permits before publishing responses. Writer-routed
closures do the same after the existing commit and head-resync checks. A timeout
does not cancel accepted work, and a lost response no longer performs caller-side
counter compensation. Dropped queued commands release their accounting before
disconnecting their response channels. Supervisor error context remains intact
on the actor and writer-handle entry points.

Counter overflow or underflow latches an accounting failure. Clearing the head
or last-error text cannot reopen accounting; admission stays closed until the
store is reopened. Timeout and saturation totals also use checked increments.
An overflowing sum of terminal totals classifies the writer as dead.

Receipt append computes its next claim count before committing the transaction.
Head resync and checkpoint successor arithmetic reject exhaustion explicitly.
The remaining pending-range clamps are documented: a fully archived live prefix
has zero pending entries, and a range upper bound is limited by the latest
representable committed sequence. The wall-clock regression policy remains in
Correction 4A.

## Typed checkpoint predecessors

Schema version 7 adds `kernel_checkpoints.previous_checkpoint_sha256`. Insertions
bind it from the verified Rust checkpoint body. All three transparency
projections copy that column, and full and incremental reads compare it against
the signed body. The nullable predecessor columns require lowercase, 64-character
text; witness predecessors additionally remain non-null. BLOB values reject.

The append-only trigger retains every sequence, genesis and continuity rule.
Its two predecessor-presence checks now use the typed column. Keeping those SQL
bytes unchanged would retain a second JSON parser and contradict Packet 10.4's
single-parser requirement. No SQL parser now derives a signed checkpoint field.
The old trigger exists only as a version 6 migration test fixture.

Main and archive upgrades run inside their existing IMMEDIATE schema
transactions. They verify checkpoint signatures, scalar columns, genesis and
predecessor links before populating the new column. Projection rows survive the
constraint rebuild, so existing divergence is rejected rather than silently
repaired. Invalid signed evidence or inconsistent projections roll back the
main schema, guards and version together. Archive co-copy comparison includes
the new column, and writable archive opening retains its existing responsibility
for materializing empty transparency projection shells. Serving has one schema
and no alternate old-column decoder.

## Approval cleanup and fixture structure

Removed `BatchApproval`, `BatchApprovalStore`, `InMemoryBatchApprovalStore` and
`SqliteBatchApprovalStore`, including the backend, exports and orphan-only test.
There was no production owner for pattern matching followed by separate usage
updates. This removes that unsupported authorization surface instead of
preserving a compatibility wrapper. Submitting multiple decisions for existing
request-bound approvals remains covered by the kernel tests. Crate documentation
and the human approval proposal now describe that actual boundary.

Checkpoint and receipt-evidence test helpers now live in a separate Rust module.
The support file is below its ordinary size limit, so its old allowlist entry
was removed. No size cap or assertion baseline was raised.

## Arithmetic inventory

The [inventory](2026-09-27-arithmetic-inventory.tsv) preserves all 638 source
anchors at `4c35ce7867`. This batch classifies 41 more entries: 28 repaired sites,
four removed API sites, four retired helper/comment matches, two updated
fixtures and three intentional bounds. Cumulative status is **101 classified,
including 47 repaired sites; 537 pending**. Every original source anchor was
checked against the base commit. Raw atomic increments repaired in this batch
extend beyond the original search for `saturating_` and `wrapping_`.

## Verification

Local profile: Linux aarch64, `umask 022`, locked dependencies, one Cargo owner,
`CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`,
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`, existing lane-d target directory.

- `/tmp/chio-writer-checkpoint-focused.log`: 89 kernel tests passed; SQLite had
  132 passed and three failed. Two old writer fixtures retained the previous
  health/error or compensation assumptions. A coherent checkpoint-fork fixture
  needed to update the new predecessor column to reach its intended rejection.
- `/tmp/chio-writer-checkpoint-focused-2.log`: nine kernel tests passed; SQLite
  had 197 passed and two failed. One fixture hardcoded the prior schema version.
  The new archive test attempted a full projection audit through the inspection
  opener before the documented writable backfill. Both fixtures were corrected.
- The first hygiene failure exceeded the support-file cap by one line. After
  extracting its evidence helpers, the gate required removal of the now-obsolete
  allowlist entry. Both failures are retained in the hygiene logs.
- `/tmp/chio-writer-checkpoint-final.log`: 201 SQLite tests and nine kernel
  approval tests passed, zero failed or ignored. This includes all 11 new
  regressions. Build: 2m 14s. Test execution: 33.21s and 0.10s respectively.
- `/tmp/chio-writer-checkpoint-hygiene-complete.log` and
  `/tmp/chio-writer-checkpoint-negative-final.log`: both gates exited zero.
  The negative-assertion baseline remains 1287. Touched Rust formatting and
  `git diff --check` also passed. No workspace build, workspace lint, full
  retention property rerun or scale campaign was used for this batch.

The final command, with the profile above, was:

```sh
cargo test --locked -j 2 -p chio-store-sqlite -p chio-kernel --lib -- \
  receipt_store::receipt_commit_actor_tests \
  receipt_store::tests::writer_checkpoint_boundaries \
  receipt_store::tests::single_writer receipt_store::tests::checkpoint \
  receipt_store::tests::background_checkpoints receipt_store::tests::bootstrap \
  receipt_store::tests::schema_archive receipt_store::tests::attempted_cost \
  receipt_store::tests::errors receipt_store::tests::verified_head \
  receipt_store::tests::retention::rotation_archives_to_freshest_verified_checkpoint_despite_stale_head \
  schema_version::tests::every_own_file_store_stamps_application_id \
  approval::tests kernel::tests::approval_flow
```

New regression coverage includes dropped queues, partial unwind with another
command still active, idempotent completion, admission and terminal counter
exhaustion, timeout exhaustion, impossible liveness totals, real append rollback,
typed predecessor substitution, main-schema migration and restart, transactional
upgrade refusal, and archive upgrade with preserved signed bytes.

Packet 3 and Correction 3A remain partial. The historical retention runner stall,
stable-candidate scale campaigns, 537 inventory entries and Packet 2 native
qualification remain open. This batch makes no hosted, merge or release claim.
