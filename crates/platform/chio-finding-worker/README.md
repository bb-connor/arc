# chio-finding-worker

Linux library for authorized finding-job execution through the Firecracker
jailer. It connects fenced PostgreSQL jobs to digest-pinned guest assets,
bounded vsock transfers, host resource accounting, and signed worker results.
The executable wrapper lives in the products group.

## Usage

Sign and verify a bounded job capability offline. The sample keys and digests
are illustrative; verification requires the independently expected authority.

```rust
use chio_core_types::{Ed25519Backend, SigningBackend};
use chio_finding_worker::{
    sign_job_capability, verify_job_capability, FindingWorkerCapabilityBody,
    FINDING_WORKER_CAPABILITY_SCHEMA,
};

let authority = Ed25519Backend::generate();
let capability = sign_job_capability(FindingWorkerCapabilityBody {
    schema: FINDING_WORKER_CAPABILITY_SCHEMA.into(),
    capability_id: "capability-1".into(),
    tenant_id: "tenant:acme-1".into(),
    job_id: "job-1".into(),
    job_kind: "finding.verify".into(),
    request_sha256: "a".repeat(64),
    job_spec_sha256: "b".repeat(64),
    not_before_unix_secs: 1,
    expires_at_unix_secs: 20,
    max_attempts: 3,
}, &authority)?;
verify_job_capability(&capability, &authority.public_key(), 10)?;
assert!(verify_job_capability(&capability, &authority.public_key(), 21).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Executing a job additionally requires a Linux KVM host, root-owned pinned
worker/Firecracker/jailer binaries and guest images, provisioned tenant artifact
storage, distinct nonroot jail identities, and PostgreSQL worker credentials.

## Guarantees

- `verify_job_capability` validates fields, expected signer, signature, and
  validity window. The executor also binds the capability to the retained job.
- `FirecrackerExecutor::execute_cancellable` validates original canonical job
  bytes, stages verified assets, enforces deadlines, and runs the jailer.
- The generated VM configuration includes vsock and omits network interfaces;
  jailer arguments retain default seccomp and apply namespace/cgroup limits.
- `verify_attested_result` validates the worker signer and result/request
  binding. The executor checks output digests and reconciles host usage.
- `HostedFindingWorker` renews leases, cancels and drains execution on shutdown
  or batch failure, and commits results through fenced store operations.

## Status

Implemented Linux-only execution library. Unit tests inspect protocol rejection,
jailer configuration, resource reconciliation, and cancellation cleanup.
Running those tests exercises local logic; VM execution needs separately
provisioned KVM, guest supervisor, images, artifacts, and database state.
Worker signatures attest this configured execution path and its result bindings.
They do not independently establish the truth of a finding or authorize payment.

## Related

- [Architecture](ARCHITECTURE.md)
- [PostgreSQL adapter](../chio-finding-market-store-postgres/README.md)
- [Worker executable source](../../products/chio-finding-worker/src/main.rs)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)

Licensed under [Apache-2.0](../../../LICENSE).
