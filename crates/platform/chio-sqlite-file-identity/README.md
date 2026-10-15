# chio-sqlite-file-identity

Inspect the device, inode, and link count of the exact main-database descriptor
held by a `rusqlite::Connection`, and the space available on its filesystem.
Chio store custody checks use this identity to compare SQLite's opened file
with a separately retained filesystem identity.

## Usage

The example opens a temporary file database using the workspace's bundled
SQLite and checks its link count. Inspection requires a supported Unix VFS.

```rust
use chio_sqlite_file_identity::inspect_main_database_file_identity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("identity.sqlite3");
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("CREATE TABLE probe(value INTEGER);")?;
    let identity = inspect_main_database_file_identity(&connection)?;
    assert_eq!(identity.link_count, 1);
    Ok(())
}
```

`tempfile` is a development dependency. The connection owns the database;
inspection borrows it synchronously and returns a copied `SqliteFileIdentity`.

## Guarantees

- `inspect_main_database_file_identity` uses SQLite file-control pointers,
  checks the VFS name, file-object size, VFS ownership, method pointer, and
  descriptor availability, then calls `fstat` on the borrowed descriptor.
- `descriptor_file_identity` neither closes nor duplicates that descriptor,
  preserving SQLite's process-level POSIX locks.
- Missing main files, unavailable pointers, and unsupported VFS/platform
  paths return errors. Non-Unix inspection always refuses.
- `SqliteFileIdentityInspectionError` separates syscall I/O failure from
  validation refusal. `main_database_file_identity` returns either error as
  its diagnostic string.
- `main_database_available_bytes` validates the same borrowed descriptor, then
  calls `fstatvfs` on it and returns `f_bavail * f_frsize` as checked `u64`
  bytes. It never reopens or stats the database path, so a renamed, replaced,
  or unlinked path still reports the held file's filesystem. Zero available
  blocks returns zero; a zero fragment size refuses with `ZeroFragmentSize`
  and a product beyond `u64` with `CapacityOverflow`.
- `SqliteAvailableSpaceError` keeps the descriptor refusal as `Identity`, the
  `fstatvfs` failure as `Io`, and exposes both through `Error::source`.

Callers must validate owner, permissions, regular-file type, expected identity,
and acceptable link count. A successful inspection can report an unlinked
file with link count zero. It performs no custody acquisition, migration,
transaction, synchronization, or rollback protection. Available space is an
observation only: it reserves no space and grants no write capacity.

## Status

Implemented for the pinned bundled SQLite Unix file layout. The runtime
checks require a VFS name beginning with `unix`; callers must preserve the
workspace's bundled-build assumption. Tests cover descriptor identity and
available space after path replacement and unlink, in-memory refusal, typed
errors, available-space arithmetic, and lock preservation against a competing
process. This crate declares no Cargo features.

## Related

- [Architecture](ARCHITECTURE.md)
- [SQLite store custody](../chio-store-sqlite/README.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)

License: [Apache-2.0](../../../LICENSE).
