# Passport and certification registry writes

Passport-status and certification registries use one file transaction for each
publish, revoke or dispute operation. The transaction takes a nonblocking writer
lock, loads the current file, validates the change and its capacity, atomically
replaces the file, and synchronizes the parent directory before releasing the
lock. Service handlers and local CLI commands use this same transaction. Production handlers and CLI commands mutate the freshly loaded registry; they
do not persist a copy loaded before another writer's revocation. The update
closure is trusted application code, not a validation boundary for arbitrary Rust
callers.

The service admits at most two registry writes at once across the process. It
returns HTTP 503 immediately when the lane or registry lock is busy. A cancelled
request retains its permit and file lock until the blocking transaction ends.
Authentication precedes admission. A successful response means persistence
completed; a persistence error after replacement can indicate uncertain
durability, so inspect the current registry before deciding how to retry.

HTTP errors retain the existing meanings: lock or lane contention is 503, load
failure is 409, a rejected mutation is 400 (or 404 for an absent record), and
persistence or unsupported-platform failure is 500.

## Capacity for revocation

The file read limit remains 16 MiB. Each admitted record reserves its maximum
remaining encoded growth into terminal revocation. Admission checks compact JSON
bytes plus the sum of that headroom. The calculation includes JSON escaping and
the bounded revocation reason, rather than assuming every reason uses one byte
per character. A refusal leaves the existing registry unchanged unless the
persistence error explicitly reports replacement without confirmed durability.

Older files written without this reserve retain a compatibility boundary. When
their reserved size already exceeds the cap, an update must fit the read cap and
must not increase reserved size. A file already exactly at the cap can therefore
still refuse a revocation that would grow its encoding. This accepted legacy
limitation remains an operator archival follow-up; it does not establish
unconditional revocation capacity for arbitrary old files.

## File custody and supported writer scope

The lock is the stable sibling `.<registry filename>.lock` in the canonical parent
directory. It is a private, single-link regular file owned by the service user.
Directory aliases resolve to the same lock. A registry path that is itself a
symbolic link is refused. A different hard-link filename is a different registry
entry because atomic replacement changes only that directory entry.

Preserve the lock file while any writer can be active. It has no stale PID to
clear: the operating system releases the advisory lock when its file descriptor
closes. Removing or replacing the file can divide cooperating writers across
different lock inodes.

The supported exclusion boundary is cooperating processes on one host using the
same registry entry. Multi-host writes to shared network storage are outside
this contract. Platforms without the implemented Unix locking primitive refuse
updates rather than perform an unlocked write. Issuance-offer and verifier-policy
registry transactions remain separate follow-up work.

These are component contracts. They do not imply foundation merge, trusted
capture, outside-team preview or release qualification.
