# chio-sqlite-file-identity

Inspect the device, inode, and link count of the exact main-database descriptor
held by a `rusqlite::Connection`, the space available on its filesystem, and
its SQLite write geometry.
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
- `main_database_write_geometry` first runs the same identity inspection, then
  queries `SQLITE_FCNTL_RESERVE_BYTES` with -1, which reports the current or
  pending reserved bytes without changing them, and reads the main file's
  public `xSectorSize` and `xDeviceCharacteristics` and its VFS name. It
  refuses a reserve outside `0..=255`, a sector size that is not a power of two
  in `32..=65536`, negative device flags, and a missing or non-UTF-8 VFS name.
  A nonzero reserve is reported, not refused; pricing decides whether it is
  supported. `SqliteWriteGeometryError` keeps the identity refusal as its
  source and records the failed file control and its SQLite status.

Callers must validate owner, permissions, regular-file type, expected identity,
and acceptable link count. A successful inspection can report an unlinked
file with link count zero. It performs no custody acquisition, migration,
transaction, synchronization, or rollback protection. Available space and
write geometry are observations: they reserve no space and grant no write
capacity or writer authority.

## Write frame prices

`price_transaction_write_shape` bounds the WAL frames, WAL bytes and
overlapping disk bytes of one committed transaction from its tree write
shapes and a checked page-size profile, including FULL commit padding.
`price_without_spill`, `price_within_pages` and `maximum_page_growth` give
the no-spill price, the page-ceiling price and the most pages one transaction
can append. Each calculator has a v1 descriptor that the owning recipe binds.

The shapes are data and cannot inspect a connection. The owning recipe
proves each shape's premise against the actual catalog before choosing its
price, and otherwise prices a valid conservative shape:

- distinct fresh keys for insertions;
- for same-key rewrites, a real unchanged-key overwrite: no secondary or
  partial index over a rewritten column, and no foreign-key delete and
  reinsert (a rewritten column that is a child key of a foreign key into the
  same table, or a parent key with an ON UPDATE action). Foreign keys, which
  the bundled build enables by default, may stay enabled when the catalog
  and the changed columns prove both cases absent;
- for a split rewrite, every same-key premise plus a generation-only change;
- every attempted producer mutation, including writes a statement or
  savepoint rollback later discards, with no credit for discarded writes;
- stored-row byte bounds in the file's authenticated text encoding; the
  calculator takes byte counts and is encoding agnostic;
- the connection settings each price assumes.

`SqliteFramePriceProfileData::checked` takes the page size, the reserved
bytes and the observed `auto_vacuum` mode, and refuses every mode other than
NONE (0). Every price and page-growth bound shares that validated profile:
pointer-map pages, commit-time page relocation and incremental vacuum are
outside every term. The owning adapter reads the mode from its verified
actual file before selecting any price.

Trigger effects belong to the complete writer catalog. Prices perform no I/O,
reserve no storage and grant no write authority.

## Write capacity amounts

`require_physical_write_capacity` checks a priced write against this file's
pending WAL and remaining debts, plus the disk debt of other files on the
same volume. Intake requires current WAL below 64 MiB, total WAL below
128 MiB, and a 128 MiB disk floor. Prepaid progress requires total WAL below
128 MiB and a 16 MiB disk floor. Equality at either WAL threshold refuses;
exact coverage of the disk floor and all debts succeeds. Every sum and
amount operation is checked.

Amounts and the intake/progress selector are data. Callers authenticate file
identity, the complete debt inventory and prepaid purpose, and hold the
required writer ownership while observing capacity and committing. This
function performs no I/O, allocates no reserve and grants no write authority.

## File custody

`custody::private_directory` accepts a directory owned by the effective user
that neither group nor others can write. `custody::private_file` accepts a
regular, single-link file owned by the effective user with mode 0600.
`custody::device_inode` returns the device and inode that identify a file
across reopen, and `custody::read_exact_at` and `custody::write_all_at` do
positioned I/O that refuses a short read or a zero-length write. Every
function returns `ErrorKind::Unsupported` off Unix. The checks take metadata
the caller already holds; callers choose the refusal for a failed check and
keep their own path, symlink and identity policy.

## Status

Implemented for the pinned bundled SQLite Unix file layout. The runtime
checks require a VFS name beginning with `unix`; callers must preserve the
workspace's bundled-build assumption. Tests cover descriptor identity and
available space after path replacement and unlink, in-memory refusal, typed
errors, custody owner and mode checks, positioned I/O, available-space arithmetic, and lock preservation against a competing
process. Geometry tests cover an actual file, pending reserved bytes, and
validation boundaries. This crate declares no Cargo features.

## Related

- [Architecture](ARCHITECTURE.md)
- [SQLite store custody](../chio-store-sqlite/README.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)

License: [Apache-2.0](../../../LICENSE).
