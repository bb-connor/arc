# chio-active-response-authority

Pre-admitted policy and artifact lookup behind Chio's active-response authority
process boundary. Operators build a reviewed SQLite snapshot; the Linux daemon
serves exact lookups from the verified startup image to a pinned broker peer.
The library also validates deployment configuration and builds authority stores.

## Usage

Validate a runtime configuration without opening a database or socket. The
identities and digests below are illustrative; daemon startup additionally
requires a validated combined deployment, matching process identity, private
store, and transferred signing-key descriptor.

```rust
use chio_active_response_authority::{AuthorityRuntimeConfig, AUTHORITY_RUNTIME_CONFIG_SCHEMA};
use chio_core::Keypair;
use chio_secure_ipc::PeerIdentity;
use chio_security_types::{ports::{Digest32, ACTIVE_RESPONSE_AUTHORITY_PROTOCOL}, ResponseExecutionMode};

let service = PeerIdentity { process_id: 100, user_id: 200, group_id: 300 };
let client = PeerIdentity { process_id: 101, user_id: 201, group_id: 301 };
let mut config = AuthorityRuntimeConfig {
    schema: AUTHORITY_RUNTIME_CONFIG_SCHEMA.into(),
    protocol: ACTIVE_RESPONSE_AUTHORITY_PROTOCOL.into(),
    response_execution_mode: ResponseExecutionMode::DryRun,
    socket_path: "/run/chio/response-authority.sock".into(),
    store_path: "/var/lib/chio/response-authority.db".into(),
    trusted_service_uid: service.user_id,
    service_identity: service,
    expected_client_peer: client,
    trusted_client: Keypair::from_seed(&[2; 32]).public_key(),
    authority_identity: Keypair::from_seed(&[1; 32]).public_key(),
    deployment_digest: Digest32::new([3; 32]),
    store_digest: Digest32::new([4; 32]),
    timeout_ms: 1_000,
    maximum_clock_skew_seconds: 5,
    maximum_replay_entries: 1_024,
    worker_count: 4,
    queue_capacity: 16,
};
config.validate()?;
config.expected_client_peer.process_id = service.process_id;
assert!(config.validate().is_err());
# Ok::<(), chio_active_response_authority::AuthorityError>(())
```

The crate declares no Cargo features. Store and runtime exports are gated to
Unix, and the serving runtime requires Linux. The example uses configuration
validation only and does not start the daemon.

## Guarantees

- `load_runtime_config()` reads a bounded canonical combined deployment and
  validates its digest, role separation, paths, and Unix file custody.
- `build_authority_store()` validates records before creating private, new
  outputs and reopens the completed store against its pinned digests.
- `AuthorityStore::open()` checks schema, canonical rows, logical digest,
  record consistency, and database file identity before retaining lookup maps.
- `artifact_lookup_key()` commits to the complete `ResponsePlan` and admission
  artifact reference. Artifact validation uses `authorization_body()` for the
  separate compact authorization commitment.
- `PreAdmittedAuthorityHandler` requires policy and plan execution modes to
  match the configured live/dry-run mode. Unknown inputs are permanently rejected.
- `AuthorityDaemonRuntime::build()` checks the current Linux process identity
  and an inherited private key file containing exactly 32 bytes.

## Status

Implemented Linux service with configuration, store, custody, and authenticated
process tests. Responses return reviewed policy selections and artifact drafts;
the broker and kernel perform the remaining admission and execution checks.
Deployment activation and operational acceptance require the host's rollout
process and configured authorities.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Security types](../chio-security-types/README.md)
- [Secure IPC](../chio-secure-ipc/README.md)

License: [Apache-2.0](../../../LICENSE).
