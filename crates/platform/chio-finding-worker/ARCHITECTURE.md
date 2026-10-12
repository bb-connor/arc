# chio-finding-worker architecture

## Responsibility and boundary

This Linux-only library owns the worker protocol, Firecracker host executor,
and one bounded PostgreSQL worker-service batch. `HostedFindingWorker` owns a
store and executor. `FirecrackerExecutor` owns validated configuration, signing
backend, execution capacity, and the pool of jail UID/GID identities.

The library authenticates job authorization and result binding. Applications
supply the capability authority and worker signer, trusted guest supervisor,
immutable images, tenant CAS inputs, and database worker role. Finding validity
and financial settlement are separate application decisions.

## Structure

`protocol.rs` defines capabilities, job specifications, requests, transfer
headers, guest results, guest-enforcement evidence, and signed attested results.
`executor.rs` validates the host, stages jails and artifacts, invokes the jailer,
exchanges bounded frames over vsock, reconciles usage, and cleans up.
`service.rs` claims jobs, renews leases, retries failures, and persists outcomes.
`lib.rs` re-exports these types and is gated by `target_os = "linux"`.

## Authorization and input flow

`sign_job_capability` validates fields before creating an export envelope.
`verify_job_capability` checks the independently expected authority, signature,
and inclusive validity window. Capabilities bind tenant, job id/kind, request
hash, job-spec hash, validity, and an attempt budget between 1 and 20.

`FindingWorkerJobSpec::validate` checks immutable repository reference, archive
commitment, canonical manifest hash, command arguments, resource limits, and
artifact names/digests/sizes. It allows at most 64 arguments and 256 input
artifacts. Repository and artifact sizes must fit the signed workspace bound.

`FindingWorkerRequest::from_job` decodes the original canonical payload under
a 4 MiB bound, verifies retained payload digest and signed identity, and bounds
the execution deadline by signed and local windows. Inputs come from an opaque
tenant-specific content-addressed namespace. Transfer descriptors commit each
stream's size and hash; an input-end marker binds the complete transfer count.

## Host execution and result flow

`FirecrackerWorkerConfig::validate` checks absolute normalized paths, asset
hash encodings, strong Ed25519 authority, host limits, and unique nonzero jail
UIDs/GIDs. `FirecrackerExecutor::new` validates configuration and worker signing
key. It does not inspect installed assets; preflight is a separate operation.

`preflight_host` checks root execution, trusted parent ownership, executable
and image digests, jail/artifact root ownership, and the `/dev/kvm` character
device. Execution repeats preflight under cancellation/deadline control. Staging
copies verified images into a unique jail and supplies the VM configuration.

The jailer runs with a new PID namespace, cgroup-v2 limits, file-size/open-file
limits, and default seccomp. The machine has vsock and no network-interface
configuration. Host cgroup accounting includes VMM headroom; the signed guest
limits describe workload process, file-descriptor, CPU, and memory boundaries.
The digest-pinned supervisor supplies in-guest enforcement evidence.

The executor validates result identity before receiving outputs. Output
artifact paths, sizes, digests, resource usage, and guest enforcement must bind
the request. Host counters prevent signed usage from underreporting observed
usage. `verify_attested_result` checks the expected worker signer and all
request-bound attestation fields. Asset digests in the verifier are checked for
format; a consumer must separately compare them with its accepted image/binary
pins. The executor fills those digests from its verified configuration.
Successful execution returns a canonical
signed envelope and guest classification for store completion.

## Lease, retry, and cleanup invariants

`run_once` bounds a claim batch by host capacity and 100. Tenant-limited variants
also bound this caller's batch; PostgreSQL independently enforces tenant lease
concurrency across replicas. Effective attempts are the minimum of worker
configuration and signed authorization. Exhausted jobs receive a fenced terminal.

While execution runs, the service renews its lease. A failed renewal cancels and
awaits execution cleanup before returning the store error. Cancellation drains
all executions and relinquishes leases where still owned, refunding the attempt.
Executor failures retry with bounded exponential delay or become exhausted.
Guest terminal results, including guest rejection, are retained as completed
job results and classified separately in `HostedWorkerRun`.

Identity permits and cleanup guards hold resources through execution. Cleanup
checks generated jail/cgroup path identity before deletion. Cancellation is
cooperative across staging, transfer, execution, and service batch draining.

## Dependencies and verification

The PostgreSQL adapter supplies job records and fenced transitions.
`chio-core-types` supplies signatures, canonicalization, and digests;
`chio-security-types` supplies clock types. Tokio and tokio-util provide process,
IO, timing, and cancellation; nix supplies identity/ownership operations;
SHA-256 verifies files and UUIDs name unique jails.

`cargo test -p chio-finding-worker --lib` exercises capability/deadline binding,
original-byte identity, output rejection, guest-enforcement matching, tenant CAS
separation, jailer arguments, credential-free child environment, host-usage
reconciliation, and cancellation/draining. These are local tests. Actual guest
execution requires root, KVM, pinned assets, a compatible supervisor, and a
migrated database with the accepted worker-role grants.
