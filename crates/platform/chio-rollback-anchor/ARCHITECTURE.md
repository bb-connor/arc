# chio-rollback-anchor architecture

## Responsibility and boundary

The crate owns the public surface `RollbackGenerationAnchor` and
`require_separate_snapshot_domain`. It stores one monotonic generation and head per
protected scope outside the SQLite database and refuses a database whose
generation or head no longer matches. It does not own the database, its schema, its
transactions, the generation column or the content behind a head; each
store reads its own `StoreHead` and passes it in. Ownership, permission and positioned-I/O checks come from
`chio_sqlite_file_identity::custody`, which the serving rollback anchor in
`chio-store-sqlite` shares.

## Structure and dependencies

`src/lib.rs` holds the slot codec, the anchor type and the process-local
lock registry; `src/tests.rs` holds the unit tests. `chio-core-types` supplies canonical JSON,
SHA-256 hex and the bounded untrusted JSON decoder. `libc` supplies
`O_NOFOLLOW`, `serde` the record encoding and `uuid` the v7 instance id.
`tempfile` creates private roots for tests.

## Data and control flow

`open` validates the root, opens or creates the scope file with mode 0600 and
`O_NOFOLLOW`, checks its metadata and records its device and inode.
`bind_initial_while` writes the first record with a fresh instance id around
the caller's store creation. `verify` and `verify_while` decode both slots,
select the committed record and compare its store generation and head with
the caller's. `advance_while` writes a prepared record into the inactive slot,
runs the caller's operation, then commits the record with `fsync` before
returning. `advance_while` refuses a step that changes the head binding. Reopen
reconciles an interrupted prepare against the caller's store head. Every write takes the process lock for the file path and
rechecks the file identity.

## Trust and invariants

Slot decoding is a trust boundary: lengths are bounded by the 512-byte slot,
checksums are verified before parsing, and payloads pass the bounded
untrusted JSON decoder with unknown and missing fields denied, so a slot
without a store head is corrupt. A `Chained` head must be lowercase SHA-256
hex, and both slots must carry the same head binding. A corrupt slot never
outranks a valid committed record. Every failure is fail-closed and returns
an error string; no path grants a generation the anchor did not commit. The
anchor proves only that the database generation and head match the anchor.
A `CounterOnly` store is not protected against a fork that reaches the same
generation with different content; a `Chained` store is. Qualified stores
must keep the anchor root on a separate device.

## Verification

Unit tests cover distinct global instance ids, prepared initial recovery for
an empty store only, recovery from a marker-cleared inactive slot, prepared
generation and torn commit marker recovery after the store commit, a
malformed marker that stays corrupt, and a failed store commit that leaves
the prior generation usable, an equal-generation fork refused by a
`Chained` anchor, a refused head binding change, and a slot without a store
head that loads as corrupt. Store tests in `chio-store-sqlite` exercise the
anchor through the stores that hold one. Run
`cargo test -p chio-rollback-anchor`.
