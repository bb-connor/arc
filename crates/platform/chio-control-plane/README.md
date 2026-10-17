# chio-control-plane

`chio-control-plane` assembles Chio kernels and implements the trust-control
HTTP service and client. It loads policies, installs guards, connects authority
and persistence stores, and hosts receipt, revocation, budget, federation,
passport, certification, and finding-market handlers.

The library's main entrypoints are `policy::load_policy`, `build_kernel`,
`DurableAdmissionRuntime`, and `trust_control::serve`. Embedding applications
own tool-server registration, service configuration, and runtime adapters.

## Usage

Build a kernel with a local joint admission authority and durable receipt store.
This offline example uses the existing `tempfile` development dependency and a
Unix filesystem with private temporary directories. All state is temporary.

```rust
use chio_control_plane::{
    build_kernel, configure_receipt_store, policy::load_policy,
    DurableAdmissionRuntime,
};
use std::os::unix::fs::PermissionsExt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let policy_path = state.path().join("policy.yaml");
    std::fs::write(&policy_path, "{}\n")?;
    let policy = load_policy(&policy_path)?;
    let admission = DurableAdmissionRuntime::open(
        &state.path().join("admission.sqlite3"),
    )?;
    let mut kernel = build_kernel(policy, &admission.kernel_keypair());
    admission.attach(&mut kernel, None)?;
    configure_receipt_store(
        &mut kernel,
        Some(&state.path().join("receipts.sqlite3")),
        None,
        None,
    )?;
    drop(kernel);
    drop(admission);
    Ok(())
}
```

The empty policy grants no default capabilities. `build_kernel` installs the
native default guard profile and the loaded policy's pipelines.
`DurableAdmissionRuntime::attach` supplies admission operations, tool outcomes,
budget, and revocation ports under one mutation fence. It verifies any selected
DPoP descriptor against the store's active authority before startup
reconciliation. Deployment initialization must provision that authority before
serving DPoP-required grants.
Register tool servers and issue scoped capabilities before invoking tools.

For HTTP hosting, construct a `trust_control::TrustServiceConfig` and pass it
to `trust_control::serve`. This starts its own Tokio runtime and listener.
`trust_control::service_runtime::client::build_client` constructs an
authenticated client; `build_public_client` supports public discovery reads.

## Features

| Feature | Default | Effect |
|---------|---------|--------|
| `default` | Enabled, empty | Enables no optional crate features. |
| `fuzz` | Disabled | Exposes the Unix active-response authority protocol fuzz entrypoint. |
| `pq` | Disabled | Forwards post-quantum support to `chio-core`, `chio-kernel`, and `chio-store-sqlite`. |

The kernel dependency always enables its `finding-market` feature. This crate
has no finding-market Cargo switch; serving depends on configured authorities
and installed runtime adapters.

## Guarantees

- `policy::load_policy` validates kernel configuration, builds guard pipelines,
  and hashes runtime policy material. HushSpec loading also resolves, validates,
  and compiles the policy and binds referenced threat-intelligence assets.
- `configure_receipt_store` rejects competing local/remote choices and in-memory
  SQLite paths, waits for the local writer, and checks web3 evidence prerequisites.
- `DurableAdmissionRuntime::open` requires filesystem-backed admission state.
  `attach` rejects a kernel signing key that differs from its bound identity.
- `configure_capability_authority` rejects conflicting authority options and
  client-side policy-gated remote issuance. The trust service owns those gates.
- `TrustServiceConfig::validate` checks transport, token separation, database
  aliases, authority custody options, and incompatible joint/cluster stores.
- `build_kernel_with_active_defense` checks the supplied runtime's readiness,
  installs security guards first, and orders raw-output and final flow hooks
  around the existing post-invocation pipeline.

## Status

The manifest marks this library as a public entrypoint and sets `publish = false`.
Kernel builders require callers to attach persistence and authority components.
Policy defaults disallow ephemeral receipt and revocation state.

The router implements operator and public HTTP surfaces. Finding routes are
compiled with default features, but `trust_control::serve` installs no purchase,
seller-submission, rail, authority-status, or challenge executor. Explicit
`serve_with_finding_*` compositions install these dependencies and validate the
shared authority path and mutation fence. Configured routes can still refuse
requests when authority admission, runtime availability, or evidence fails.

Cluster replication uses authenticated pulls, deterministic leader selection,
and quorum gates. Deployments with a clustered SQLite capability authority must
provision its replication anchor out of band. Keyring authority and local joint
admission authority each reject peer cluster replication.

Tests exercise local stores, HTTP adapters, and composed finding flows. Fixture
trust and injected test rails have a bounded scope; deployment acceptance also
requires the operator's installed verifiers, transports, and persistence owners.

## Related

- [Architecture](ARCHITECTURE.md)
- [Trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [SQLite persistence](../chio-store-sqlite/README.md)
- [Kernel](../../kernel/chio-kernel/README.md)
- [License](../../../LICENSE)
