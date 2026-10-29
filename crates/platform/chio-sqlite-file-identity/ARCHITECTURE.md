# chio-sqlite-file-identity architecture

## Responsibility and boundary

The file inspection surface contains `SqliteFileIdentity`,
`SqliteFileIdentityInspectionError`, `inspect_main_database_file_identity`,
`main_database_file_identity`,
`main_database_available_bytes`, `SqliteAvailableSpaceError`, and
`main_database_write_geometry` with `SqliteWriteGeometryData`,
`SqliteWriteGeometryError`, `SqliteGeometryFileControl`, and
`SqliteGeometryMethod`.
`SqliteFileIdentity` copies three `u64` fields: device, inode, and link count.
The caller owns the connection and keeps it borrowed throughout inspection.

The crate owns the narrow unsafe boundary needed to inspect SQLite's actual
main-file descriptor. Store callers combine that result with filesystem
custody checks. Identity inspection does not validate ownership, permissions,
regular file type, expected identity, or a required link count. The safe
`custody` module supplies those owner, mode, link-count and positioned-I/O
checks as predicates over caller-held metadata and descriptors; the rollback
anchors in `chio-rollback-anchor` and `chio-store-sqlite` share them. It neither acquires
serving locks nor retains a descriptor beyond the call. Available space and
write geometry are data: the crate reserves no space and grants no write
capacity or writer authority.

## Structure and dependencies

Descriptor extraction, identity inspection, and their tests live in
`src/lib.rs`. `src/available_space.rs` and `src/available_space/tests.rs` hold
the available-space inspection and its tests. `src/write_geometry.rs` and
`src/write_geometry/tests.rs` hold the write geometry observation and its
tests. `src/custody.rs` holds the custody predicates and positioned I/O with
their tests. Unix-only code imports SQLite
FFI and defines `BundledUnixFilePrefix`, a C-layout copy of the audited prefix
containing method, VFS, inode-information, and descriptor fields. The non-Unix
implementations return a validation refusal.

`rusqlite` provides the borrowed connection and SQLite FFI. The workspace
selects `rusqlite` 0.39 with the `bundled` feature;
the prefix assumption belongs to that pinned SQLite build. `libc` supplies
`fstat`, `fstatvfs`, and target-specific metadata. `nix` supplies the
effective user id for custody ownership checks. `tempfile` creates isolated databases
for tests and the README example. The manifest declares no Cargo features.

## Data and control flow

`inspect_main_database_file_identity` obtains the SQLite handle from the
borrowed connection. It calls `sqlite3_file_control` for `main` with
`SQLITE_FCNTL_FILE_POINTER` and `SQLITE_FCNTL_VFS_POINTER`.
Each result must be `SQLITE_OK` and supply a non-null pointer.

The returned VFS must have a UTF-8 name beginning with `unix` and report
enough file-object bytes for `BundledUnixFilePrefix`. `read_unaligned` copies
that prefix without imposing stronger alignment. The prefix's VFS must match
the reported VFS, its methods pointer must be non-null, and its descriptor
must be nonnegative. The private `main_database_descriptor` returns that
descriptor as a `BorrowedFd`. SQLite may close or replace that descriptor
during an operation on the same connection, such as VACUUM, so it is valid
only while no SQLite operation or callback runs; each caller passes it
directly to one syscall. `inspect_main_database_file_identity` passes it to
`fstat`.

On syscall success, `descriptor_file_identity` copies the device, inode, and
link count into the result. On failure it retains `std::io::Error` as the
`Io` variant and exposes it through `Error::source`. Validation failures carry
a diagnostic string and have no underlying error source.
`main_database_file_identity` converts the typed error with `to_string`.

`main_database_available_bytes` uses the same `main_database_descriptor`, so
every check above applies, and keeps its refusal as the `Identity` variant.
It passes the borrowed descriptor to `fstatvfs` and keeps a syscall failure as
`std::io::Error` in the `Io` variant. On success it multiplies `f_bavail` by
`f_frsize` in `u128` and returns the product as `u64`. A zero fragment size
refuses with `ZeroFragmentSize` and a product beyond `u64` with
`CapacityOverflow`; zero available blocks returns zero. Both arithmetic
variants have no error source.

`main_database_write_geometry` first calls
`inspect_main_database_file_identity` and keeps its refusal as the `Identity`
variant, so the same supported, live, bundled Unix main descriptor is required.
It then calls `sqlite3_file_control` on `main` with
`SQLITE_FCNTL_RESERVE_BYTES` and -1. SQLite reports the larger of the
requested and actual reserve and changes nothing for a value outside
`0..=255`. It then takes `SQLITE_FCNTL_VFS_POINTER` and, last,
`SQLITE_FCNTL_FILE_POINTER`. A non-`SQLITE_OK` status is kept in `FileControl`
with its control, and a null pointer is `NullPointer`. The file's public
`xSectorSize` and `xDeviceCharacteristics` methods are called with no SQLite
call between `FILE_POINTER` and those reads, and no pointer is retained,
because SQLite may replace the main file during a later operation on the
connection. The VFS name is copied from the registered VFS. The sector size must be a power of two in `32..=65536`, the range
SQLite's pager uses without clamping; device flags must be nonnegative; and
`powersafe_overwrite` tests `SQLITE_IOCAP_POWERSAFE_OVERWRITE` from
`rusqlite::ffi`. A nonzero reserve in `0..=255` is reported unchanged.

## Trust and invariants

The unsafe reads depend on SQLite's pointer lifetime and the workspace's
bundled Unix layout. Runtime name and size checks narrow the accepted VFS;
they do not independently authenticate a substituted implementation with a
matching name. Keep the dependency/build assumption intact when using this
boundary. Memory connections lack a usable main-file descriptor and fail.

Inspection calls `fstat` or `fstatvfs` directly on the descriptor SQLite
holds. Closing even a duplicate descriptor can release process-wide POSIX locks
on that inode, so the helpers never duplicate or close it, and never reopen or
stat the database path. It also performs no SQL query,
schema write, commit, or pragma change. The caller's current transaction and
SQLite connection lifecycle remain under that caller's control.

The result identifies the open file even if its pathname has been renamed or
replaced. Unlinking it produces link count zero while its device and inode
remain observable. Custody callers must compare against their expected
identity and reject the link counts and permissions their contract forbids.
This observation supplies no crash-durability or rollback guarantee.

## Write frame prices

`src/write_liability.rs` derives checked frame bounds from the pinned bundled
SQLite 3.51.3: a cursor depth of `BTCURSOR_MAX_DEPTH` (20), `balance_nonroot`
neighbors (`NB` 3, `apNew[NB+2]`), 24-byte frame and 32-byte WAL headers,
FULL commit padding to at most a 65536-byte sector, `usableSize - 4` overflow
payload and the lock-byte page an append skips. A new record walks the tree
once; a possibly existing record, or a repeated write of an absent key, walks
it three times and keeps its old and intermediate overflow images. Same-key
rewrites walk once each and charge one old and one new image set bounded by the
larger image of every row; they hold only for a real unchanged-key overwrite,
with no secondary or partial index over a rewritten column and no
foreign-key delete and reinsert (`sqlite3FkRequired` returning 2). A split
rewrite inherits those premises, charges in-place overwrites for same-width
rows and the full cascade plus doubled images for growing rows. The
no-spill price writes each dirty page once and adds page one, the final
original freelist trunk and one slack frame. `src/write_liability/tests.rs`
asserts exact refusals and arithmetic, and `src/write_liability/tests/real_sqlite.rs` measures
real WAL frames and page growth against the prices, controls the foreign-key
delete and reinsert path, and stores a per-row overflow rounding workload.

Every price and page-growth bound requires `auto_vacuum` NONE: the profile
refuses any other observed mode, because pointer-map pages, commit-time page
relocation and incremental vacuum are outside every term. Shapes count every
attempted producer mutation, including writes a statement or savepoint
rollback discards, and take stored-row byte counts in the file's
authenticated text encoding.

These are data calculations. They do not authenticate the caller, the shape's
premises or the connection settings, and they reserve no WAL or disk.

## Managed write capacity

`src/write_capacity.rs` owns checked WAL/disk byte amounts and the v1 capacity
policy. `src/write_capacity/tests.rs` exercises exact boundary and arithmetic
refusals. Debt amounts require disk bytes to cover WAL bytes. Arithmetic
validates both operands and the result; overflow and underflow refuse.

For pending WAL P, current write C, remaining debt D and other same-volume
disk debts O, intake requires P + C.wal < 64 MiB. Both stages require
P + C.wal + D.wal < 128 MiB. Available disk must be at least
C.disk + D.disk + sum(O.disk) plus 128 MiB for intake or 16 MiB for prepaid
progress. Other files' WAL bytes never consume this file's WAL limit.

The owning store supplies authenticated observations and binds the descriptor
into its financing profile. The arithmetic does not authenticate debt, select
a prepaid purpose, price physical writes, synchronize writers or reserve
storage. Physical pricing and native funding remain responsibilities of
their respective owners.

## Verification

Unix tests compare the observed identity with filesystem metadata, replace
the pathname while retaining the connection, and inspect the original file
after unlink. Available-space tests read the held file after rename,
replacement, and removal of every path, then require SQLite to refuse a write
with `SQLITE_READONLY_DBMOVED` while the pre-move row stays readable, and
refuse a memory database with the identity validation. In-memory tests verify main-file refusal. Typed-error
tests check successful inspection and the actual `EBADF` source of `fstat` and
`fstatvfs` on an invalid descriptor. Arithmetic tests check the exact product,
zero available blocks, and the `ZeroFragmentSize` and `CapacityOverflow`
refusals.

Write-geometry tests observe an actual file inside a write transaction and
then commit a write, report a pending reserve of 32 bytes on repeated queries
without changing it, refuse a memory database through the identity guard, and
check the reserve, sector-size, and device-flag validation boundaries.

Lock-preservation tests start an exclusive transaction in DELETE journal mode,
inspect identity through both public APIs and available space, and launch a
separate test process.
That process attempts `BEGIN IMMEDIATE` with zero busy timeout and must receive
`DatabaseBusy`. The probe is marked ignored because its parent test supplies
the database through `CHIO_IDENTITY_LOCK_PROBE_DATABASE`.

Custody tests accept a 0700 directory and a 0600 single-link file and refuse
group-writable modes and a second hard link; positioned I/O tests round-trip
bytes at an offset and refuse a short read with `UnexpectedEof`.

Run `cargo test -p chio-sqlite-file-identity` for these tests. Non-Unix tests
check the explicit unsupported-platform diagnostics. The README example
requires Unix and the workspace's bundled SQLite VFS.
