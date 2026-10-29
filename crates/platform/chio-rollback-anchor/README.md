# chio-rollback-anchor

Detect an in-place restore of an older SQLite store image by keeping the
store's generation and head in a separate, private anchor file.

## Usage

A store opens one anchor per protected scope, binds it in the same step that
creates the store, and advances it around every generation-changing write:

```rust,ignore
use chio_rollback_anchor::{require_separate_snapshot_domain, RollbackGenerationAnchor, StoreHead};

require_separate_snapshot_domain(&database_path, &anchor_root)?;
let anchor = RollbackGenerationAnchor::open(&anchor_root, scope_bytes)?;
let current = StoreHead::chained(generation, head_sha256);
anchor.verify(&current)?;
let next = StoreHead::chained(generation + 1, next_head_sha256);
anchor.advance_while(&current, &next, || commit_write())?;
```

## Guarantees

- The anchor file is `{scope_sha256}.generation-anchor` under a root owned by
  the effective user and not writable by group or others. The file must be a
  regular, single-link, owner-only (0600) file opened with `O_NOFOLLOW`.
- Each record lives in one of two 512-byte slots tagged `CHIOG1OK` with a
  length and SHA-256 checksum. A torn or corrupt slot never replaces the
  last committed record.
- Each record binds a `StoreHead`: the store generation plus an
  `AnchorHead`. `AnchorHead::Chained` carries the SHA-256 of the store's
  content-binding history head; `AnchorHead::CounterOnly` binds the counter
  alone. A store keeps one binding for the life of its anchor.
- `verify` refuses a store generation or head that differs from the
  committed record, and a head binding that differs from the one recorded. `advance_while` prepares the next record, runs the caller's
  operation and commits only after it succeeds, so a crash leaves a prepared
  record that the next open reconciles.
- Each anchor records a UUIDv7 instance id, read through `instance_id`,
  which a store binds into its own state.
- `require_separate_snapshot_domain` refuses an anchor root on the same
  device as the database. Path separation alone is not a rollback boundary.
- Non-Unix platforms refuse every operation.

A `CounterOnly` anchor detects a restored image at a different generation
but not a fork that reaches the same generation with different content. A
`Chained` anchor detects both.

The anchor detects a restored database file. It cannot detect a restore that
rolls back the anchor root together with the database, which is why the
snapshot-domain check is required for qualified stores.

## Related

- [Architecture](ARCHITECTURE.md)
- [SQLite file identity and custody](../chio-sqlite-file-identity/README.md)
- [SQLite store](../chio-store-sqlite/README.md)

License: [Apache-2.0](../../../LICENSE).
