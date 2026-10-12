# chio-finding-market-canary

Provisions and verifies an exact hosted finding-worker canary job, or exercises
publication and tenant isolation through a deployed HTTPS market listener.
The binary binds observations to the profile's candidate and configuration
revision and emits canonical JSON reports for the operation it performs.

## Usage

This offline rejection example checks the private input path gate before
profile loading or PostgreSQL I/O. Run from the workspace root.

```sh
if diagnostic=$(cargo run --locked -p chio-finding-market-canary --quiet -- --profile profile.json --job job.json verify 2>&1); then
  exit 1
fi
test "$diagnostic" = canary_file_invalid
```

For an existing completed canary, invoke `chio-finding-market-canary --profile
/absolute/path/hosted-profile.json --job /absolute/path/canary-job.json verify`.
Both inputs must be private, effective-user-owned regular files containing
canonical JSON, with a maximum of 4 MiB per file.
Set `CHIO_FINDING_CANDIDATE_SHA` to the lowercase 40-character candidate SHA
matching the job and profile. Set the profile's runtime database URL variable
and provide its PostgreSQL CA. Verification reads retained job state and needs
exactly one enabled tenant and one completed job with the expected signed result.

`provision` uses the same inputs and inserts one pending job into an empty
tenant queue. The worker must execute that job before `verify` can succeed.
The signed job capability binds the request and job specification to the
profile's kernel public key and permits one attempt.

`network` accepts `--finding-pool`, `--tenant-id`, `--isolation-tenant-id`, and
seller, buyer, and isolation-buyer credential environment names via
`--seller-key-id-env`, `--seller-key-secret-env`, `--buyer-key-id-env`,
`--buyer-key-secret-env`, `--isolation-buyer-key-id-env`, and
`--isolation-buyer-key-secret-env`. It rejects `--job`. Supply distinct enabled
API-key tenants, a private pool of 2 through 128 live signed findings from one
issuer, and positive `GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT` values.
This command publishes a fresh finding and requires a deployed HTTPS endpoint.

## Guarantees

- `validate_job` checks candidate, tenant, configuration, request digest, job
  specification digest, and the capability's pinned signature and attempt limit.
- `provision` verifies the empty queue and the retained single pending job.
  `verify` checks completion, one attempt, result digest, worker signature,
  binary and image digests, and successful guest resource-boundary probes.
- `network_canary` checks release identity, fresh publication, exact retry,
  buyer resolution and catalog content, and an isolation-tenant 404.
- `network_egress_contract` pins the HTTPS authority, denies loopback,
  link-local, and IPv6 ULA destinations, disallows redirects, and caps
  response bodies at 2 MiB.

## Status

This unpublished Unix executable implements bounded canary operations. Unit tests
cover candidate binding, workflow-attempt identity, pool constraints, catalog
pagination, CLI inputs, and egress restrictions. Positive worker verification
requires a retained execution result; network acceptance requires a deployed
listener and scoped credentials. Reports describe the checks performed.

## Related

- [Architecture](ARCHITECTURE.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)
- [Worker daemon](../chio-finding-worker/README.md)
- [PostgreSQL store](../../platform/chio-finding-market-store-postgres/README.md)

Licensed under [Apache-2.0](../../../LICENSE).
