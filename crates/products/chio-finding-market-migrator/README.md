# chio-finding-market-migrator

Applies the hosted cognition market's PostgreSQL schema migrations through
the `chio-finding-market-migrate` binary. It gives schema changes a separate
credential boundary from the HTTP server and worker processes.

## Usage

The following offline rejection example checks the required absolute CA path
before reading credentials or connecting to PostgreSQL. Run from the workspace
root; the command succeeds only when the expected rejection occurs.

```sh
if diagnostic=$(cargo run --locked -p chio-finding-market-migrator --quiet -- --ca-certificate ca.pem 2>&1); then
  exit 1
fi
test "$diagnostic" = finding_market_migrator_arguments_invalid
```

To apply migrations, supply a dedicated migration-role URL in
`CHIO_FINDING_MARKET_MIGRATOR_DATABASE_URL` and the absolute trusted CA path in
`CHIO_FINDING_MARKET_CA_CERTIFICATE`. The latter variable is a shell convenience
for this example. Run against a database provisioned for these schema changes:

```sh
cargo run --locked -p chio-finding-market-migrator -- \
  --ca-certificate "${CHIO_FINDING_MARKET_CA_CERTIFICATE:?set an absolute trusted CA path}"
```

`--database-url-env` selects another environment variable; its name accepts
uppercase ASCII letters, digits, and underscores, with a maximum of 256 bytes.

The CA certificate must authenticate the PostgreSQL hostname: the underlying
configuration forces TLS `VerifyFull`. `--acquire-timeout-millis` defaults to
5000 and accepts 100 through 30000. The migrator uses one connection.
Its role must pass the store's migration privilege checks, including
`BYPASSRLS`, `CREATE` permission on the `public` schema, and a `public`-only
search path.

## Guarantees

- `run` rejects empty, oversized, or control-containing database URLs before
  constructing `HostedPostgresConfig`.
- `PostgresFindingMarketMigrator::connect` checks the dedicated role through
  `verify_migrator_role` before exposing migration execution.
- `PostgresFindingMarketMigrator::migrate` holds an advisory lock while bridging
  the legacy ledger and running embedded SQLx migrations. Drift or unlock
  failures return errors.
- `main` returns a failing process exit code and a fixed diagnostic on error.
  Successful migration exits without a report on stdout.

## Status

This unpublished binary implements schema migration and argument validation.
Its local unit test inspects the environment-name restriction. PostgreSQL
migration behavior is exercised by the store's separate integration suite.
Deployments must provision the role and trusted CA, serialize operational
changes, and verify the resulting schema before starting runtime processes.

## Related

- [Architecture](ARCHITECTURE.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)
- [PostgreSQL store](../../platform/chio-finding-market-store-postgres/README.md)
- [HTTP server](../chio-finding-market-server/README.md)

Licensed under [Apache-2.0](../../../LICENSE).
