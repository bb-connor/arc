# chio-rollback-anchor architecture

## Responsibility and boundary

The crate owns the public surface `RollbackGenerationAnchor` and
`require_separate_snapshot_domain`. It stores one monotonic generation per
protected scope outside the SQLite database and refuses a database whose
generation no longer matches. It does not own the database, its schema, its
transactions or the generation column; each store reads its own generation
and passes it in. Ownership, permission and positioned-I/O checks come from
`chio_sqlite_file_identity::custody`, which the serving rollback anchor in
`chio-store-sqlite` shares.

## Structure and dependencies

`src/lib.rs` holds the slot codec, the anchor type, the process-local lock
registry and the unit tests. `chio-core-types` supplies canonical JSON,
SHA-256 hex and the bounded untrusted JSON decoder. `libc` supplies
`O_NOFOLLOW`, `serde` the record encoding and `uuid` the v7 instance id.
`tempfile` creates private roots for tests.

## Data and control flow

`open` validates the root, opens or creates the scope file with mode 0600 and
`O_NOFOLLOW`, checks its metadata and records its device and inode.
`bind_initial_while` writes the first record with a fresh instance id around
the caller's store creation. `verify` and `verify_while` decode both slots,
select the committed record and compare its store generation with the
caller's. `advance_while` writes a prepared record into the inactive slot,
runs the caller's operation, then commits the record with `fsync` before
returning. Reopen reconciles an interrupted prepare against the caller's
generation. Every write takes the process lock for the file path and
rechecks the file identity.

## Trust and invariants

Slot decoding is a trust boundary: lengths are bounded by the 512-byte slot,
checksums are verified before parsing, and payloads pass the bounded
untrusted JSON decoder with unknown fields denied. A corrupt slot never
outranks a valid committed record. Every failure is fail-closed and returns
an error string; no path grants a generation the anchor did not commit. The
anchor proves only that the database generation matches the anchor, so
qualified stores must keep the anchor root on a separate device.

## Verification

Unit tests cover distinct global instance ids, prepared initial recovery for
an empty store only, recovery from a marker-cleared inactive slot, prepared
generation and torn commit marker recovery after the store commit, a
malformed marker that stays corrupt, and a failed store commit that leaves
the prior generation usable. Store tests in `chio-store-sqlite` exercise the
anchor through the stores that hold one. Run
`cargo test -p chio-rollback-anchor`.
