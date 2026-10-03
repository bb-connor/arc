# Private custody for a SQLite capability authority

`SqliteCapabilityAuthority` stores its signing seed as plaintext in the database
and may write it to SQLite's WAL or rollback journal. Its file permissions are
local access controls. They provide neither encryption nor external key custody.
A process running as the authority's effective user, or as root, remains able to
read or replace this material.

On Linux, the authority requires a dedicated directory owned by
its effective user with mode `0700`. The database and any existing `-wal`, `-shm`
or `-journal` files must be regular, single-link files owned by that user with mode
`0600`. Missing directories and the empty database are created with these modes
before SQLite can write a seed. Existing permissions are validated, never repaired
by opening the authority.

Every path component must be a real directory rather than a symlink. Ancestors
must belong to the effective user or root and cannot be writable by other users.
A root-owned or effective-user-owned sticky directory such as `/tmp` is permitted
above the private authority directory. `/tmp/authority.db` itself is refused
because its immediate parent is not private. Relative filenames use the same
checks against the current working directory.

Each authority handle pins the database and directory identities. Replacing or
unlinking its database, changing custody permissions, introducing an unsafe
sidecar, or replacing a parent causes subsequent operations to fail. SQLite's
borrowed main-file descriptor is checked without opening and closing a second
descriptor, which could disturb its process-scoped locks. A fresh explicit open
is not a persistent rollback detector; authenticated replication and recovery
requirements still apply.

The implementation fails closed before filesystem mutation on every other OS,
including Darwin and BSD. Linux mode bits also limit the effective POSIX ACL
mask; that property is not assumed for other ACL systems. An equivalent ownership,
ACL and database-descriptor identity contract must be qualified before enabling
those platforms.

## SQLite URI paths

Local `file:` URI filenames are decoded once before the custody checks. An empty
authority or `localhost` is allowed; the optional query parameters are
`mode=rw`, `mode=rwc`, and `cache=private`. `mode=rw` requires an existing database.
SQLite receives the resulting absolute filesystem path with URI interpretation
disabled. Literal filesystem paths retain their literal percent, question-mark
and hash characters.

Duplicate or unknown parameters, URI fragments, malformed percent encodings,
embedded NUL, dot traversal, remote URI authorities, memory databases and temporary
databases are refused before creating directories or files. Options that change
locking, VFS, read-only or immutable behavior are not accepted.

## Offline migration of an existing authority

This is an operator action. Do not run a permission migration during serving,
create a fresh authority to make an open error disappear, or repin a replication
stream as part of a filesystem migration.

1. Record the intended service user, exact database path, current public key,
   generation and authenticated replication checkpoint using the existing
   deployment's trusted operational records. Keep a recoverable offline backup
   under equivalent private custody. If earlier permissions exposed the seed,
   evaluate key compromise and the separately authenticated rotation/revocation
   procedure; restricting access does not undo disclosure.
2. Stop every process that can open this database, including peers, background
   jobs and administrative SQLite sessions. Keep the database and its WAL,
   shared-memory and rollback-journal files together. Do not delete a WAL or
   journal to obtain a clean open or copy a live database file alone.
3. Inspect the complete path while offline. Refuse symlinks, extra hard links,
   unexpected owners or replaceable ancestors. Resolve them through the
   deployment's established backup/recovery procedure before proceeding. The
   authority directory must be dedicated to the service user. If it is shared,
   relocate the complete stopped database using that recovery procedure and
   update the configured path.
4. For an existing dedicated directory with verified ownership and identity,
   restrict the directory to `0700` first, then set the database and each existing
   `-wal`, `-shm` and `-journal` file to `0600`. Perform these explicit offline
   changes as the service user or administrator. Do not recursively chmod a shared
   data directory, and do not change a symlink target or an unverified inode.
5. Reopen as the intended service user with the new custody checks. Confirm the
   recorded public key, generation and authenticated checkpoint before enabling
   traffic. Exercise a normal operation and inspect any recreated WAL/SHM modes.
   Retain the original backup and migration evidence according to the deployment's
   secret-material retention policy.

Creation and validation tests include an isolated subprocess with umask `022`,
existing loose modes, unsafe parents and sidecars, symlinks, hard links, replacement,
reopen, rotation, replication and refused opens that write no seed material. These
tests establish the local filesystem boundary; hosted release qualification and
operator migration remain separate acceptance steps.
