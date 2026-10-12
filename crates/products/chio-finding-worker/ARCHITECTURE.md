# Finding worker daemon architecture

## Responsibility and boundary

The package `chio-finding-worker-daemon` owns the `chio-finding-worker`
executable. Its directory is `crates/products/chio-finding-worker`.
The separate platform package `chio-finding-worker` owns guest protocols,
Firecracker execution, lease heartbeats, and durable job transitions.
The daemon owns startup checks, tenant scan scheduling, dependency failure
handling, tick reporting, and continuous-mode shutdown.
It exposes no Rust library API.

The process consumes a hosted profile and worker-scoped credentials.
Host artifact provisioning, remote signing custody, PostgreSQL roles, and
tenant registration are operator responsibilities.
The worker connects through the store's dedicated worker-role boundary.

## Structure

`src/main.rs` contains the executable and unit tests.
`Args` declares profile path, worker identity, one-shot selection, and polling
interval. `DaemonError` exposes fixed operational error codes.
`TenantRuntime` pairs a tenant id with its configured durable limits.
`WorkerTickSpec` carries scan budgets, cancellation, and failure policy.
`TenantFailureState` retains consecutive failures and an open-until timestamp.
`WorkerTickReport` records readiness, dependency error, visit and outcome counts,
claimed and completed ids, and per-job evidence.
The package declares no Cargo features.

## Data and control flow

`run` validates arguments, loads and validates the profile, matches the running
executable to its configured file, and checks the CA path.
`load_worker_executor` validates and loads the remote Worker signer before
constructing the Firecracker executor. The executor's host preflight runs
before the database connection and any queue claim.

The daemon connects with the profile's worker URL and verifies every enabled
tenant's artifact namespace and durable limits. `enabled_tenants` rejects an
empty enabled set. `HostedFindingWorker::new` receives lease duration,
heartbeat interval, maximum attempts, and a five-second retry base.

One-shot mode scans from the first tenant, uses the profile's maximum tenant
and job budgets, and fails when a tenant is unavailable. It emits one canonical
tick report with `ready` set to true if that pass succeeds.
It does not install the continuous shutdown handler.

Continuous mode tracks database readiness and rotates the first tenant after
each successful pass. A tenant claim limit is its concurrency limit capped by
the remaining tick job budget. Unavailable tenants advance their own breaker
and are skipped after the configured threshold for 30 seconds.
A successful library run clears that tenant's dependency failure state even
if the run contains rejected or exhausted jobs.

Store failures update the database breaker. Three failures open it for
30 seconds and cause unready dependency reports. Other mapped execution
errors terminate the daemon. Successful scans reset database failure state.
Polling waits observe the shutdown future between passes.

## Trust and invariants

`validate_arguments` bounds worker identity to 256 bytes of permitted ASCII
and polling to 100 through 60000 milliseconds, requiring an absolute profile.
`read_profile` checks initial file length against 4 MiB, effective-user
ownership, private permissions, a regular file, and a no-follow open.
It compares device and inode and requires canonical JSON byte equality.
The subsequent `read_to_end` is unbounded and does not recheck length, so the
initial metadata limit does not bound a concurrent file growth during reading.
Typed deserialization rejects unknown fields. The full profile validator
checks hosted settings.

`require_current_binary` rejects a configured symlink and matches device and
inode with `current_exe`. Artifact digests and trusted host paths are checked
by the executor. `require_trusted_ca` checks a regular, nonempty CA file,
initial size at most 4 MiB, no group or other write bits, and matching inode
after a no-follow open. The PostgreSQL configuration forces TLS `VerifyFull`.

The worker URL must be nonempty, at most 16384 bytes, and contain no controls.
`PostgresFindingMarketStore::connect_worker` owns role and schema checks.
The daemon verifies durable concurrency, queue, spend, and revision limits
against the profile before running any tenant.
Tick counters use checked arithmetic. A successful tick reports scheduling
and dependency status; completed job ids and evidence establish job outcomes.

Continuous shutdown cancels the active library call and awaits it for the
configured grace period. Timeout emits `shutdown_timeout` and exits with
`worker_shutdown_handler_failed`. Other successful shutdown paths emit an
unready report with `shutdown` and return success.

## Dependencies

`chio-control-plane` supplies profile validation and executor custody loading.
`chio-finding-worker` supplies the lease-backed worker service and execution
evidence. The PostgreSQL store supplies the worker connection and tenant limits.
The hosted edge supplies circuit breakers and readiness state.
`chio-core-types` serializes canonical tick reports.
Clap, Serde, Tokio, `tokio-util`, and Unix metadata support parsing,
serialization, timers, signals, cancellation, and local file checks.

## Verification

Run `cargo test -p chio-finding-worker-daemon --all-targets` for unit tests.
Tests cover worker identity validation, error mapping, unready dependency
reports, tenant breaker opening and recovery, one-shot tenant failures, and
clearing dependency failures after job-local terminal outcomes.
The README refusal example verifies the absolute-path argument gate.

Guest execution acceptance requires a provisioned Linux KVM host, exact pinned
artifacts, remote signer, and dedicated PostgreSQL worker role.
The sibling canary verifier checks the retained completed result, identity
digests, signature, and guest process and open-file enforcement evidence.
The daemon's local tests do not execute that host path.
