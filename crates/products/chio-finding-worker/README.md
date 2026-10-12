# chio-finding-worker-daemon

Runs the hosted cognition market's isolated worker service through the
`chio-finding-worker` binary. It connects the PostgreSQL worker role to the
Firecracker executor in the platform `chio-finding-worker` library, scans
enabled tenants, and emits canonical JSON tick reports.

## Usage

This offline rejection example checks argument validation before profile
loading, signing custody, host preflight, or database I/O. Run from the workspace
root; successful shell execution means the rejection matched.

```sh
if diagnostic=$(cargo run --locked -p chio-finding-worker-daemon --quiet -- --profile profile.json --worker-id worker:example --once 2>&1); then
  exit 1
fi
test "$diagnostic" = worker_arguments_invalid
```

For a bounded queue pass, invoke `chio-finding-worker --profile
/absolute/path/hosted-profile.json --worker-id worker:example --once`.
The profile must contain canonical JSON in a private regular file owned by
the effective user. Its configured worker executable must match the running
binary's device and inode, and its pinned artifacts must pass executor checks.

Execution needs a Linux host with Firecracker, jailer, readable and writable
`/dev/kvm`, trusted kernel and rootfs images, provisioned tenant artifact stores,
and the executor's host privilege boundary. Set the profile's worker database
URL and Worker remote signer token variables, and provide its trusted CA.
The PostgreSQL worker role, tenant limits, and configuration revision must
match the profile. `--once` performs these preflights even for an empty queue.

Omitting `--once` polls continuously. `--poll-interval-millis` defaults to 1000
and accepts 100 through 60000. Worker ids accept 1 through 256 ASCII letters,
digits, or `-`, `_`, `.`, `:`, and `/`. Use a unique identity for each replica.

## Guarantees

- `validate_arguments` requires an absolute profile path and bounded worker
  identity and polling interval.
- `run` calls profile validation, executable and CA checks, remote custody
  loading, host preflight, tenant artifact preflight, and durable limit checks
  before constructing `HostedFindingWorker`.
- `run_tick` bounds tenants visited and jobs claimed using profile budgets.
  One-shot mode returns an error on tenant unavailability.
- Continuous operation isolates tenant failures with a 30-second breaker and
  opens the database breaker after three failures for 30 seconds.
- `write_report` serializes each tick as canonical JSON followed by a newline.

Continuous mode handles SIGINT and SIGTERM, cancels the active tick, and waits
up to the profile's shutdown grace before failing on timeout.

## Status

This unpublished daemon implements process preflight, bounded queue scans,
failure handling, reporting, and continuous shutdown. Unit tests cover argument
rules, error mapping, readiness reports, and tenant breaker behavior. Running
the guest path requires the configured Linux host, database, artifacts, and
remote signing custody. A ready tick can contain zero completed jobs.

## Related

- [Architecture](ARCHITECTURE.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)
- [Worker library](../../platform/chio-finding-worker/README.md)
- [Canary verifier](../chio-finding-market-canary/README.md)

Licensed under [Apache-2.0](../../../LICENSE).
