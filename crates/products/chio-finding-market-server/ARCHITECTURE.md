# Hosted market server architecture

## Responsibility and boundary

The binary owns process startup, private profile loading, database connection
selection, release identity binding, and shutdown notification.
`chio-finding-hosted-edge` owns authentication and HTTP handling.
`chio-finding-market-store-postgres` owns durable market state and role checks.
The executable has no exported library API.

HTTP serving requires a trusted proxy profile and binds only loopback.
An external proxy owns HTTPS termination and forwards authenticated traffic.
The profile's native TLS variant cannot start this executable's HTTP path:
`run` requires `load_trusted_proxy` to return a configured proxy.

## Structure

`src/main.rs` contains `Args`, `ServerError`, and the startup functions.
`read_profile` and `open_private_regular` implement the configuration-file gate.
`deployed_release_identity` constructs the identity reported by the edge.
`run_replication_checks`, `write_replication_checks`, `run_replication_round`,
and `write_replication_check` implement the independent freshness path.
`ReplicationRoundOutcome` retains attempted and successful tenant counts.
`shutdown_signal` handles SIGINT and, on Unix, SIGTERM.
The package declares no Cargo features.

## Data and control flow

Startup reads an absolute private canonical profile and validates the complete
`FindingHostedProfile`. Replication flags branch away from HTTP startup
immediately after validation.

The HTTP path loads trusted proxy credentials, configures a TLS PostgreSQL
runtime pool, and connects the store. It creates a `HostedAuthenticator` using
profile-derived authority configuration and an API-key pepper.
It checks the deployed candidate and artifact environment bindings, parses
kernel and penalty authority public keys, and creates `HostedHttpServerState`.
Only after those steps does it bind the loopback socket and serve with a
shutdown future.

The freshness path connects `PostgresFindingMarketReplicator` with its separate
URL and at most eight pool connections. It loads the AuthorityStatus remote
signer, including that signer's key preflight, and attempts every enabled
tenant concurrently using a Tokio `JoinSet`.
Each tenant check reads authority state and the current projection digest,
signs a `HostedReplicationCheckBody`, and appends it to PostgreSQL.

One-shot mode fails if any tenant check fails. Continuous mode refuses an
initial round with no successes, logs partial failures, and stops after three
subsequent consecutive rounds with no successes. It accepts intervals of
5 through 20 seconds and observes the same shutdown signal as the listener.

## Trust and invariants

The profile reader requires effective-user ownership, a regular file, and
zero group or other permissions before and after opening with `O_NOFOLLOW`.
It matches device and inode, reads at most 4 MiB plus one byte, rejects a
length change, and compares the bytes with canonical JSON serialization.
`FindingHostedProfile::validate` then checks configuration semantics.

Serving compares `CHIO_FINDING_DEPLOYED_CANDIDATE_SHA` and
`CHIO_FINDING_DEPLOYED_ARTIFACT_SHA256` to the profile release fields.
This validates supplied identity strings; the executable does not measure its
own binary digest. The profile's kernel and penalty keys enter the HTTP state.
The configured HTTP body and concurrency limits are 4 MiB and 1024.

Freshness requires PostgreSQL authority, enabled mutations, matching
configuration revision, and a writable mode: `RollbackWindow`,
`Authoritative`, or `Retired`. It rejects `Shadow` and `Frozen`.
Checks bind the authority epoch and outbox sequence. The local projection
digest fills both digest fields with zero lag, differences, and security
counters; the command does not compare an independent source database.
Append conflicts and digest mismatches retry within a five-second window.

Replication mode does not run HTTP startup's trusted proxy or deployed release
environment checks. It still validates the complete profile and needs the
configured database role and remote signing service.
`ServerError` preserves contextual causes; missing secrets name the environment
binding. Errors produce a failing process exit code.

## Dependencies

`chio-control-plane` validates the hosted profile and loads credentials and
remote signers. `chio-core-types` provides canonical JSON, public keys, and
signed export envelopes. The hosted edge provides the listener, authentication,
metrics, and release identity types. The PostgreSQL store supplies durable
state, authority checks, and replication operations.
Clap parses flags, Tokio supplies sockets, signals, timers, and concurrent
rounds, and `zeroize` wraps database URL copies loaded by the executable.

## Verification

Run `cargo test -p chio-finding-market-server --all-targets` for the in-file
tests. They exercise relative-path rejection, private canonical regular-file
requirements, symlink and oversized-file rejection, release drift, writable
authority modes, continued attempts after one tenant fails, and complete
round failure accounting.

The README runs the pre-I/O relative-path rejection and checks its diagnostic.
The package's unit tests do not establish a deployed proxy, database role
configuration, remote signing custody, or network reachability. A complete
startup and an external authenticated request require those operator systems.
