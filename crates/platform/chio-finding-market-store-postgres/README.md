# chio-finding-market-store-postgres

PostgreSQL durability for Chio's hosted finding market: tenant-scoped jobs,
authentication state, revisioned domain events, projections, spend reservations,
replication, and retention evidence. It implements the store-neutral ports
used by the hosted HTTP edge and supplies fenced leases to workers.

## Usage

Prepare bounded connection settings offline. `new` parses the DSN;
connecting is a separate asynchronous operation.

```rust
use std::time::Duration;
use chio_finding_market_store_postgres::{
    HostedPostgresConfig, HostedTenantId,
};

let config = HostedPostgresConfig::new("postgres://market@db.example/chio")?
    .with_max_connections(8)?
    .with_acquire_timeout(Duration::from_secs(2))?
    .with_max_jobs_per_tenant(1_000)?;
let tenant = HostedTenantId::new("tenant:acme-1")?;
assert_eq!(tenant.as_str(), "tenant:acme-1");
assert!(format!("{config:?}").contains("[REDACTED]"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`PostgresFindingMarketStore::connect` checks runtime privileges and the complete
SQLx ledger. `connect_worker` checks the narrower worker role. Schema application
uses `PostgresFindingMarketMigrator::connect` and `migrate` with separate
credentials. Every connection uses `PgSslMode::VerifyFull`.

## Features

| Feature | Default | Effect |
|---------|---------|--------|
| `postgres-integration` | Off | Enables test pool constructors and boundary hooks, and the `postgres_store` integration target. |

## Guarantees

- `begin_tenant` sets transaction-local tenant context and locks the enabled
  tenant; forced RLS enforces row selection and write isolation.
- `claim_due_jobs` and SQL transition functions enforce tenant concurrency,
  database-clock lease validity, worker ownership, and increasing fences.
- `HostedMarketDomainEvent::from_canonical_payload` validates typed payloads,
  aggregate identity, canonical bytes, and the required signer/authority pins.
- `recover_purchase_result` commits reveal, purchase terminal, and spend
  transition in one tenant transaction.
- `reserve_monthly_spend` uses UTC month buckets and database trigger accounting
  for reserved plus committed units, subject to the tenant's ceiling.

## Status

Implemented persistence adapter with offline unit tests and database integration
fixtures. Spend reservations and stored settlement packets record control-loop
state; payment execution belongs to the surrounding application and rail.
Migration, runtime, worker, replicator, and retention roles have distinct
privilege checks. The integration fixture requires a dedicated database and
resets its public schema. Production activation and host acceptance require
deployment-specific evidence beyond these tests.

## Related

- [Architecture](ARCHITECTURE.md)
- [Embedded migrations](../chio-finding-market-migrations/README.md)
- [Store-neutral ports](../chio-finding-market-port/README.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)

Licensed under [Apache-2.0](../../../LICENSE).
