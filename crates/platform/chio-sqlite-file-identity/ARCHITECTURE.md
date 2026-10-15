# chio-sqlite-file-identity architecture

## Responsibility and boundary

The public surface contains `SqliteFileIdentity`,
`SqliteFileIdentityInspectionError`, `inspect_main_database_file_identity`,
the compatibility wrapper `main_database_file_identity`,
`main_database_available_bytes`, and `SqliteAvailableSpaceError`.
`SqliteFileIdentity` copies three `u64` fields: device, inode, and link count.
The caller owns the connection and keeps it borrowed throughout inspection.

The crate owns the narrow unsafe boundary needed to inspect SQLite's actual
main-file descriptor. Store callers combine that result with filesystem
custody checks. This crate does not validate ownership, permissions, regular
file type, expected identity, or a required link count. It neither acquires
serving locks nor retains a descriptor beyond the call. Available space is
data: the crate reserves no space and grants no write capacity.

## Structure and dependencies

Descriptor extraction, identity inspection, and their tests live in
`src/lib.rs`. `src/available_space.rs` and `src/available_space/tests.rs` hold
the available-space inspection and its tests. Unix-only code imports SQLite
FFI and defines `BundledUnixFilePrefix`, a C-layout copy of the audited prefix
containing method, VFS, inode-information, and descriptor fields. The non-Unix
implementations return a validation refusal.

`rusqlite` provides the borrowed connection and SQLite FFI. The workspace
selects `rusqlite` 0.39 with the `bundled` feature;
the prefix assumption belongs to that pinned SQLite build. `libc` supplies
`fstat`, `fstatvfs`, and target-specific metadata. `tempfile` creates isolated databases
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
a diagnostic string and have no underlying error source. The compatibility
wrapper converts the typed error with `to_string`.

`main_database_available_bytes` uses the same `main_database_descriptor`, so
every check above applies, and keeps its refusal as the `Identity` variant.
It passes the borrowed descriptor to `fstatvfs` and keeps a syscall failure as
`std::io::Error` in the `Io` variant. On success it multiplies `f_bavail` by
`f_frsize` in `u128` and returns the product as `u64`. A zero fragment size
refuses with `ZeroFragmentSize` and a product beyond `u64` with
`CapacityOverflow`; zero available blocks returns zero. Both arithmetic
variants have no error source.

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

Lock-preservation tests start an exclusive transaction in DELETE journal mode,
inspect identity through both public APIs and available space, and launch a
separate test process.
That process attempts `BEGIN IMMEDIATE` with zero busy timeout and must receive
`DatabaseBusy`. The probe is marked ignored because its parent test supplies
the database through `CHIO_IDENTITY_LOCK_PROBE_DATABASE`.

Run `cargo test -p chio-sqlite-file-identity` for these tests. Non-Unix tests
check the explicit unsupported-platform diagnostics. The README example
requires Unix and the workspace's bundled SQLite VFS.
