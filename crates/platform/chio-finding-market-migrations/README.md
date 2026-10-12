# chio-finding-market-migrations

The compile-time SQLx migration ledger for Chio's hosted finding market.
`MIGRATOR` embeds the SQL files kept beside the PostgreSQL storage adapter,
so migration tools and runtime schema checks share the same ledger.

## Usage

Inspect the embedded migration versions without connecting to PostgreSQL.
The iterator exposes SQLx migration metadata and checksums.

```rust
use chio_finding_market_migrations::MIGRATOR;

let versions: Vec<i64> = MIGRATOR.iter()
    .map(|migration| migration.version)
    .collect();
assert!(!versions.is_empty());
assert!(versions.windows(2).all(|pair| pair[0] < pair[1]));
assert!(MIGRATOR.iter().all(|migration| !migration.sql.is_empty()));
```

Applying the ledger requires a database connection and a migration role.
The adapter's `PostgresFindingMarketMigrator` owns role validation,
legacy-ledger bridging, and its outer advisory lock.

## Guarantees

- `sqlx_macros::migrate!` embeds the migration directory at compilation;
  deployments read this embedded ledger without loading SQL from disk.
- `MIGRATOR` includes schema, RLS policies, guarded job transitions,
  domain projections, replication state, and admission accounting.
- Migration 0016 rejects retained unauthenticated delivery state before
  installing the kernel-receipt delivery contract.

## Status

Implemented embedded ledger with 24 numbered SQL migrations. This crate has
one public static and no connection constructor, application-specific role
checker, or dedicated unit tests. SQLx supplies migration execution machinery.
Database integration tests live in `chio-finding-market-store-postgres`.
Executing migrations changes schema and can reject incompatible retained data;
inspect those requirements before applying them to an existing database.

## Related

- [Architecture](ARCHITECTURE.md)
- [SQL directory](../chio-finding-market-store-postgres/migrations/)
- [PostgreSQL adapter](../chio-finding-market-store-postgres/README.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)

Licensed under [Apache-2.0](../../../LICENSE).
