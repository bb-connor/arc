# Secret Broker Architecture

## Responsibility and boundary

The broker owns encrypted credential custody, provider header injection, durable
attempt tracking, and signed execution evidence. Its public entry points include
`BrokerDaemonConfig::load`, `BrokerDaemonRuntime::build`, `BrokerIpcClient`,
`EncryptedBlobSecretBackend::open`, capability and proof helpers, receipt helpers,
and durable attempt and receipt stores. `CredentialRef` identifies a provider,
credential ID, and positive version without containing credential bytes.

`SecretBackend`, `SecretMaterial`, `ProviderAdapter`, and `PreparedProviderRequest`
are crate-private. Library callers cannot invoke their materialization or header
injection methods. The daemon constructs `BrokerService` through a crate-private
production constructor. Public `execute` methods operate on that composed service;
a supplied `TrustedExecutionContext` must match its original registered operation.

The kernel and authenticated authority own quota admission and live capability
state. The broker verifies their evidence and joins its dispatch to the captured
operation. It trusts the host service boundary and the selected provider, which
receives the credential over TLS. Host memory inspection remains outside the
credential secrecy boundary.

## Structure

| Module group | Responsibility |
| --- | --- |
| `protocol`, `capability`, `proof` | Bounded request shapes, domain-separated signatures, request constraints, and digests. |
| `daemon`, `daemon_runtime`, `service` | Admin and execution handlers, trusted configuration, composition, custody, authorization, and IPC supervision. |
| `backend`, `encrypted_blob_backend`, `inherited_fd` | Secret owners, tenant blob storage, sealed key consumption, and inherited descriptor adoption. |
| `provider`, `generic_https` | Provider-owned header preparation, destination pinning, TLS transport, response limits, and sanitization. |
| `budget`, `authority_ipc`, `revocation` | Authenticated authority operations, combined capture evidence, parent liveness, and revocation checks. |
| `store`, `sqlite`, `registration`, `reconcile`, `receipt` | Attempt identifiers and transitions, file custody, signed controls, restart recovery, and terminal evidence. |
| `provision`, `migration` | Threshold admin authorization, durable replay journal, and externally anchored migration bindings. |
| `audit`, `privileged_audit` | Salted migration reference commitments, designated-runner challenge protocol, and signed comparison evidence. |
| `kernel_admission`, `native_mcp`, `prepared_mcp` | Optional kernel admission integration, Linux launch ownership, and Unix prepared MCP proxy. |
| `host_resource`, `host_https`, `docker_adapter`, `repository_adapter` | Host-owned resource bindings and Linux adapters. |

`chio-secret-brokerd` owns serving and process hardening. `chio-broker-mcp` serves a
prepared stream over stdio. The Docker and repository adapter binaries provide
host-owned loopback HTTPS endpoints. These adapters are separate process owners
with their own trusted configuration and lifecycle constraints.

## Data and control flow

1. A host installs issuer, audience, provider, placement, tenant, authority, and
   service identity pins. Kernel integration verifies the complete typed broker
   request in both tool arguments and the supplemental extension, including the
   invocation ID. `BrokerQuotaVerifier` produces a bound supplemental claim.
2. Authenticated registration binds deterministic attempt identifiers to the
   original admission operation, complete request, quotas, authority metadata,
   and revocation domain. Preparation checks capability, proof, live parent,
   fresh revocations, destination policy, and migration posture; it retains
   credential/version custody and the prepared provider dispatch in memory.
3. Execution requires that retained preparation and durable registration.
   `execute_inner` obtains and validates the original combined capture, claims
   the captured attempt, rechecks revocations, and verifies identical capture
   evidence again at the dispatch boundary.
4. It refreshes live authorization, verifies unchanged ancestry and credential
   version, then commits `DispatchCommitted` while holding credential mutation
   coordination. Only after that durable commitment does HTTPS transport run.
5. Transport and response failures record their dispatch knowledge. Successful
   sanitized output is bound to request, capability, response body and headers,
   capture indexes, epoch, provider, and quota metadata in a signed receipt.
   Receipt persistence precedes the `Completed` attempt transition.

Preparation and kernel quota verification confer no independent dispatch
permission. A prepared IPC connection is restricted to the exact operation and
expires within 30 seconds, capability expiry, or proof expiry. The caged MCP proxy receives
that stream without the host's registration signing authority.

`replay_completed` authenticates an exact durable completion before consulting
live admission authorities. It verifies the original registration and signed
response, then closes a compatible interrupted terminal transition. Historical
replay returns the stored result and cannot renew execution permission.

## Trust and invariants

`BrokerRequest::validate_bounds` checks body size (512 KiB), header count (64),
normalized unique sorted headers, destination syntax, options, and optional
preview digest. `CallerOptions` bounds timeout to 120 seconds and combined
response head/body to 2 MiB. This structural validator permits explicit loopback
HTTP. Production capability validation and destination preflight impose the
serving transport policy. `decode_execute_request` bounds input to 1 MiB and
uses the duplicate-aware signed JSON decoder before structural validation.

`issue_capability` signs canonical JSON with a domain separator and checks the
returned identity and strict signature. `verify_capability` additionally pins
issuer, audience, algorithm, and the half-open validity interval.
`verify_request_proof` checks the configured caller key and signed request
bindings; its caller must authenticate the capability separately. Digest helpers have distinct contracts: `capability_digest` canonicalizes and
hashes its input without authenticating it.

The generic provider owns either `authorization` or `x-api-key`. Signed provider
header constraints must match that selection, and caller headers cannot supply
it. Credential bytes must fit the provider's printable header representation.
Response processing strips sensitive headers and rejects credential echoes,
ambiguous framing, and excessive sizes. Headers are normalized and stably sorted;
repeated values retain their original relative order in signed and replayed output.

Public HTTPS resolves and pins permitted addresses and validates TLS with rustls
and Web PKI roots. The installed local adapter instead pins one DNS TLS name,
loopback address, port, and leaf certificate, without DNS resolution or root
fallback. Neither route delegates destination exceptions to request arguments.

`SealedKeyFd` and `SealedSigningKeyFd` consume owner-checked, read-only descriptors
with all four required seals and exactly 32 bytes. Runtime composition requires
distinct descriptors and pins the derived broker public key. Sealed consumption
is implemented on Linux and Android; other targets return custody errors.
Secret storage uses tenant-scoped encrypted blobs and HMAC-derived reference keys.
Secrecy owners and zeroizing request buffers reduce retained plaintext lifetime.

`GovernedAdminAuthorizer` validates configured approvers, subject, threshold,
intent, and time window. Its SQLite journal durably consumes approval authority
and stores signed mutation or control completion. Exact recovery can return the
same completion after approval expiry; changed authorization or intent conflicts.
Receipt signature verification must be paired with an independently trusted
signer pin at the consuming boundary.

Runtime config v6 is canonical JSON loaded through a retained private file
identity and a bounded read. Startup checks effective UID, database ownership,
SQLite sidecars, distinct paths and file identities, service locks, sealed keys,
and externally stored migration minimum heads. `ProductionBrokerMigrationEnforcer`
rechecks provider custody and quota records at materialization and dispatch.
Posture changes or ledger replacement require rebuilding the matching composition.

Normal IPC has absolute deadlines, a service-owned private socket, and Linux peer
credential authentication. `BrokerIpcClient` pins broker PID/UID/GID, socket
identity, and receipt signer. Request faults are contained; storage, custody,
invariant, and supervision faults terminate serving. The privileged audit socket
runs on a separate supervised listener and pins the designated runner UID/GID.

## Persistence, audit, and host adapters

Preserve encrypted credentials, attempts, admin journal, and receipt database
together with tenant and signing keys. Preserve and anchor the migration ledger
independently. SQLite stores use WAL and full synchronization; actual persistence
also depends on filesystem behavior. File custody checks reject path rebinding,
hardlinks, symlinks, and unexpected ownership or permissions.

Startup reconciles persisted completions and failures, then drains recoverable
attempt pages through the authenticated authority before publishing sockets.
`UnknownOutcome` cannot redispatch. Captured attempts with durable dispatch evidence
converge to an unknown outcome when no exact completion is available. A completed
attempt missing its durable response is a storage error.

The endpoint holds an exclusive lifecycle lock and removes only its created
socket identity on orderly exit. After uncatchable termination, the supervisor
must recover the stale socket under that lock while serving is stopped. Startup
does not automatically remove an existing socket.

Privileged migration audit verifies a short-lived runner authorization and fresh
threshold operator approvals. Its two bounded canonical exchanges bind a salted
reference precommitment, broker-signed challenge, nonce, runner signature, and
exact deployment/request/authority context. It compares injected request bytes
inside broker memory without dispatch or quota mutation. Signed comparison
artifacts contain commitments and equality evidence; salts and credential bytes
remain private. `verify_broker_audit_evidence` needs independent trust context.

The Docker adapter pins daemon and container identity and checks lifetime around
exec creation, start, and exit. Its configured container requires no network,
read-only root, non-root user, and no privileged mode. The Docker daemon and its
operators remain trusted; a concurrent privileged restart can leave an uncertain
effect. Adapters never retry uncertain operations. Saved upstream/model fixtures
and supplied lifecycle evidence establish their own exercised test contexts.

## Dependencies

`chio-core-types` supplies canonical JSON, keys, and signing backends.
`chio-security-types` supplies clocks, migration contracts, and authority ports.
`chio-secure-ipc` supplies peer identity and protected Unix endpoint primitives.
`chio-store-sqlite` supplies encrypted tenant blob storage; `rusqlite` supplies
attempt, receipt, and admin transactions. `secrecy` and `zeroize` own sensitive
memory, while HMAC/SHA-256 derive references and commitments. `rustls`,
`webpki-roots`, and `url` implement HTTPS trust and destination handling.
The feature table in the [README](README.md#features) identifies optional kernel
and MCP dependencies. Apple targets also include `chio-file-custody`.

## Verification

`tests/execution.rs` exercises canonical request decoding, capability field
substitution, caller proof bindings, and header normalization.
`tests/concurrency.rs` exercises deterministic registration conflicts and retries.
`tests/production_surfaces.rs` covers governed replay, signed completion,
append-only receipt storage, and exact response recovery after reopening.
`tests/network_adversarial.rs` checks restricted address classification;
`generic_https::tests` covers deadlines, response limits, and sanitization.
Linux process and custody tests cover brokerd, inherited descriptors, prepared
MCP, and native launch boundaries. Their local authority/provider fixtures must
be identified when interpreting results.

Focused commands are `cargo test --locked -p chio-secret-broker --test execution`,
`cargo test --locked -p chio-secret-broker --test production_surfaces`, and
`cargo test --locked -p chio-secret-broker --lib generic_https::tests::`.
Kernel paths use `--features kernel-admission`; native launch tests use
`--features native-mcp`. `scripts/check-secret-broker-boundary.sh` assembles the
broader boundary campaign, including Linux enforcement compositions. Enabling
`real-linux-enforcement` selects those test paths and native MCP dependencies.
