# Migration process architecture

## Responsibility and boundary

This package owns the `chio-finding-market-migrate` executable. Its process
boundary separates schema-changing credentials from the runtime database
credentials used by the market server and workers.
It accepts a database URL environment-variable name, an absolute trusted CA
path, and a connection acquisition timeout.
There is no exported Rust library API or hosted operator profile input.

The PostgreSQL store library owns role verification, migration locking,
legacy-ledger conversion, and migration execution. The executable translates
those failures into fixed process diagnostics.
An operator owns certificate provisioning and database role creation.

## Structure

All executable code lives in `src/main.rs`.
`Args` uses Clap to declare the three command-line inputs.
`main` maps `run` into `ExitCode::SUCCESS` or `ExitCode::FAILURE`.
`run` validates input, loads the secret, constructs `HostedPostgresConfig`,
connects a `PostgresFindingMarketMigrator`, and awaits `migrate`.
The in-file `tests` module contains the environment-name test.
The package declares no Cargo features.

## Data and control flow

1. Clap requires `--ca-certificate` and supplies the environment-variable name
   and timeout defaults.
2. `run` checks the environment name, absolute certificate path, and timeout
   before reading the database URL.
3. The URL must contain 1 through 16384 bytes and no control characters.
4. The store configuration receives the CA path, one connection, and the
   requested acquisition timeout.
5. The migrator connects and checks its role before attempting schema changes.
6. The store acquires an advisory migration lock, bridges a supported legacy
   migration ledger, and runs the compile-time embedded SQLx migrator.
7. Unlocking is attempted after either success or failure. A migration or
   unlock error propagates to the executable's failing exit code.

The acquisition timeout governs the database pool. The executable does not
provide an overall migration deadline or a custom signal shutdown handler.

## Trust and invariants

`HostedPostgresConfig::connect_options` forces `PgSslMode::VerifyFull`, so the
CA path supports both certificate trust and PostgreSQL hostname verification.
`verify_migrator_role` requires `BYPASSRLS` and `CREATE` permission on the
`public` schema. It rejects superuser, `CREATEROLE`, `CREATEDB`, `REPLICATION`,
`INHERIT`, role membership, and database-level `CREATE` or `TEMPORARY`
privileges. The effective search path must contain only `public`.

The privilege boundary grants substantial schema authority. Supplying a
runtime login or a PostgreSQL superuser does not satisfy the dedicated-role
check. Role provisioning remains an administrative operation.

The store's legacy bridge checks a contiguous ledger prefix against embedded
versions, names, and SQL digests before importing it into SQLx bookkeeping.
The binary signs no artifacts and produces no readiness assertion.
Fixed error strings distinguish arguments, missing or invalid secrets,
configuration, connection, and migration failures without printing the URL.

## Dependencies

`chio-finding-market-store-postgres` implements configuration and migration
operations. Its migration dependency embeds SQL at compile time.
Clap derives the argument parser, and Tokio runs the asynchronous connection
and migration calls.

## Verification

The package unit test `secret_environment_name_is_strict` checks the invalid
character predicate using a lowercase variable name. It does not call `run`
or connect to PostgreSQL.
Run `cargo test -p chio-finding-market-migrator --all-targets` for that test.
The README's rejection example executes `run` with a relative certificate
path and verifies the exact argument diagnostic without database I/O.

The store's `postgres_store` integration test requires a dedicated database
and separate administrative, migrator, runtime, worker, retention, and
replicator logins. It changes schema and privilege state during testing.
Successful local argument tests do not establish TLS deployment, role
provisioning, or safe migration of an operator's existing database.
