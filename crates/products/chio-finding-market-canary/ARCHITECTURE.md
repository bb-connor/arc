# Finding canary architecture

## Responsibility and boundary

The executable owns exact-job provisioning, terminal-result inspection, and
an authenticated network publication probe.
Its process interface is `chio-finding-market-canary`; it exports no library
API. It consumes a hosted operator profile plus a signed worker job or a pool
of signed finding artifacts.
The PostgreSQL store owns persistence, and the worker owns guest execution.

`provision` writes one queue entry. `verify` reads the retained job and emits a
report only after validating the completed result.
`network` publishes through the deployed market API and observes retry,
resolution, catalog, and isolation behavior.
Each operation finishes after its bounded work or an error.
The binary does not install a dedicated signal shutdown handler.

## Structure

All implementation lives in `src/main.rs`.
`Args` and `Command` expose `provision`, `verify`, and `network`.
`CanaryJob` and `CanaryRequestDigest` describe the exact worker request.
`CanaryReport` carries queue and terminal observations.
`NetworkArgs`, `NetworkFindingPool`, and `NetworkCanaryReport` describe network
credentials, artifact selection, and resulting HTTP observations.
`CanaryOutput` selects the canonical stdout report shape.
The package declares no Cargo features.

`read_canonical_private_bytes` and `open_private_regular` gate input files.
`validate_job`, `provision`, and `verify` implement the database path.
`network_canary` uses `NetworkHttpClient`, publication helpers, and catalog
pagination helpers to execute the HTTPS path.

## Data and control flow

`run` first reads a private canonical profile and calls its complete validator.
For the database commands it then reads a job, verifies its bindings, creates
the tenant identity, and connects the runtime PostgreSQL store using the
profile's URL environment variable and CA.

`provision` requires zero retained jobs and zero nonterminal jobs. It stores
canonical payload bytes, rereads the job, and requires one pending entry with
the exact request and payload. Its queue checks are separate store operations.
Operators must keep unrelated producers out of the dedicated canary tenant.

`verify` requires exactly one retained job, no nonterminal jobs, completion
after one attempt, and a result matching the retained digest. It inspects the
signed worker envelope and guest enforcement evidence before reporting.
It does not launch Firecracker or contact the worker's remote signer.

The network path selects enabled API-key tenants, validates candidate identity,
and derives event identity from the positive GitHub run id and attempt.
It loads a private pool of 2 through 128 live, unique signed findings from
one issuer and orders them by a run-bound selection digest.
It checks the deployed release identity, skips findings already present,
publishes a fresh candidate, waits two seconds, and retries the same event.
It compares buyer resolution bytes and a targeted catalog entry, then requires
a 404 for the finding under the distinct isolation tenant's credentials.

## Trust and invariants

Input paths must be absolute. The file gate requires a regular file owned by
the effective user with no group or other permissions and rejects the final
symlink. Device, inode, ownership, and permissions are checked around opening.
Reads cap input at 4 MiB plus one byte, recheck length, and require canonical
JSON byte equality. Typed job and pool inputs reject unknown fields.

`validate_job` requires matching lowercase 40-character candidate strings in
the environment, profile, and job, a matching configuration revision, a
32 through 256 byte nonce, and exactly one enabled tenant matching the job.
The canonical request digest includes the job specification and profile-pinned
worker, Firecracker, jailer, kernel, and rootfs digests.
The capability must bind tenant, job identity, kind, request, and specification,
permit exactly one attempt, and verify against the profile's kernel key.

Terminal verification pins the envelope signer to the profile's Worker role
key and verifies its signature. It compares job and artifact bindings and
requires a successful result with a finding-artifact digest.
Guest enforcement must report cgroup v2 process limits and `RLIMIT_NOFILE`,
matching configured limits, passed probes, and zero limit hits.
The verifier does not independently remeasure the worker host or guest.

The network client pins the HTTPS authority through `HttpEgressContract`.
It denies loopback, link-local, and IPv6 ULA destinations, accepts no redirects,
caps responses at 2 MiB, and sets a 30-second request timeout.
Credential values are loaded by validated environment names. Isolation buyer
credentials must differ from the primary buyer's id and secret.
Release identity binds deployment id, candidate, artifact, and configuration.
The first publication must be `applied`; the retry must be `exact_replay`.

## Dependencies

`chio-control-plane` supplies profile validation and signing-role metadata.
`chio-core-types` provides canonical JSON, hashes, and public keys.
The PostgreSQL store supplies tenant-scoped jobs; `chio-finding-worker`
supplies capability, result, and guest enforcement types.
`chio-finding` verifies pool artifacts. Reqwest and `chio-egress-contract`
provide contract-mediated HTTPS. Clap, Tokio, Serde, Unix file metadata, and
`zeroize` support process inputs, transport, serialization, and secret handling.

## Verification

Run `cargo test -p chio-finding-market-canary --all-targets` for unit tests.
They cover workflow-attempt event identity, candidate drift, distinct isolation
CLI inputs, fresh publication outcome, egress restrictions, private pool
loading and duplicate rejection, and catalog cursor arithmetic.
The README rejection example exercises the pre-I/O absolute-path requirement.

Database canary acceptance needs a provisioned dedicated tenant and an actual
signed completed worker result. Network acceptance needs the deployed listener,
live finding pool, credentials, and run identity. Unit tests and the path
rejection example establish none of those runtime conditions.
