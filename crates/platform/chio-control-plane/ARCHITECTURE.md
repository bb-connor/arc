# chio-control-plane architecture

## Responsibility and boundary

This crate owns policy materialization, kernel assembly, local and HTTP-backed
store wiring, and the trust-control service. `build_kernel` returns a
`ChioKernel`; the embedding process registers tool servers and supplies durable
state. `trust_control::serve` hosts a separate HTTP service from a
`TrustServiceConfig` and runs its own Tokio runtime.

The public surface also includes `DurableAdmissionRuntime`, authority seed
lifecycle helpers, `build_kernel_with_clock`, and
`build_kernel_with_active_defense`. `CliError` carries failures from these
compositions. Client construction lives under
`trust_control::service_runtime::client`; request DTOs and configuration are
re-exported through `trust_control`.

The kernel performs invocation admission and execution. SQLite owns persisted
records and transaction semantics. Runtime adapters supply finding execution,
settlement observations, status resolution, and active-defense authorities.
The ordinary service entrypoint supplies none of the finding executors.

## Structure

| Module | Responsibility |
|--------|----------------|
| `lib.rs` | Kernel guard ordering, store selection, capability authority selection, default issuance, and seed lifecycle helpers. |
| `policy/loader.rs`, `policy/types.rs` | Chio YAML and HushSpec materialization, source/runtime identity, kernel options, and issuance policies. |
| `issuance/authority.rs`, `issuance/scope.rs` | Policy-backed authority wrappers, issued-token validation, reputation ceilings, and runtime-assurance constraints. |
| `durable_admission.rs` | Serving-owner provisioning, bound kernel identity, shared admission/outcome/budget/revocation ports, configured DPoP activation validation, and startup reconciliation. |
| `dpop_runtime.rs` | Explicit local replay-authority initialization and readback of an existing activated authority. |
| `security.rs` and `security/` | Active-defense composition, dispatch and issuance adapters, response execution, scheduling, and readiness. |
| `trust_control/config_and_public.rs` | Blocking service entrypoints and explicit finding-runtime installation with path and fence checks. |
| `trust_control/service_runtime/init.rs`, `router.rs` | Startup owners, bounded lanes, router construction, listener hygiene, and shutdown drain. |
| `trust_control/service_types/` | Configuration, application state, route constants, and request/response structures. |
| `trust_control/report_validation.rs`, `authority_admission.rs` | Bearer/peer authentication, tenant read principals, and admitted authority inspections. |
| `trust_control/cluster/` | Peer observations, leader/quorum views, authenticated authority agreement, deltas, and snapshots. |
| `trust_control/finding_*` | Market role pins, activation, purchase, seller, challenge, status, proof, and recovery adapters. |
| `evidence_export.rs` and `evidence_export/` | Evidence package writing, verified reading, import, and federation-share validation. |
| `fiscal_runtime_startup.rs` | Reconciliation against configured genesis, anchored continuity, and installed fiscal adapter registry. |

## Data and control flow

`policy::load_policy` reads a file and detects HushSpec. Chio YAML is
parsed into `ChioPolicy`, kernel options are validated, default capabilities are
materialized, and source/runtime hashes are computed. That path sets reputation,
runtime-assurance, and threshold-approval issuance policies to `None`.
HushSpec loading resolves imports, validates and compiles the specification,
materializes issuance policies, and binds threshold approval to the runtime hash.
Referenced threat-intelligence pattern bytes contribute to policy identity.
`parse_policy` only parses Chio YAML and validates its kernel configuration;
callers use the loader for full runtime materialization.

`build_kernel_with_clock` carries the supplied authority clock into the kernel
and applies durable/swarm admission settings. DPoP requires a configured
descriptor and matching activation in the attached durable authority.
It installs the default pre-invocation guards before the configured pipeline.
For active defense, the security pre-invocation guards come first. The
post-invocation order is raw-output security hooks, configured hooks, default
hooks, then the final flow join. Loaded attestation trust and threshold-approval
requirements are installed when present.

`configure_receipt_store`, `configure_revocation_store`, and
`configure_budget_store` select local SQLite or remote HTTP adapters.
`configure_capability_authority` selects a seed-file, SQLite, remote, or default
local authority and applies configured issuance gates. Remote policy-gated
issuance must be configured on the service. `require_control_token` checks that
an option exists; client construction additionally rejects blank or padded
secrets and invalid endpoints.

For joint admission, `DurableAdmissionRuntime::open` provisions a private
serving-owner lock root and filesystem database, loads its kernel seed, and
binds that signing identity to durable state. `attach` installs operation and
outcome stores and shares the joint budget/revocation ports. It validates an
optional configured DPoP descriptor against the active store before startup
reconciliation. `initialize_local_dpop_authority` provisions that authority
only during explicit deployment initialization; `load_local_dpop_authority`
requires an existing active record with its retained source generation.
`validate_durable_admission_participant_paths` rejects separate budget or
revocation databases when durable admission is enabled. Callers must invoke
that configuration validator when assembling the corresponding CLI options.

Service startup validates bootstrap configuration before preparing transport.
A configured keyring takes sole seed custody and shares an anchored receipt
writer with handlers. Startup opens the joint authority, checks any injected
purchase executor's fence, composes fiscal state, and binds the listener.
It then opens separate configured stores, provisions configured plain authority
custody, constructs cluster state, and starts receipt query snapshots.
The state owns these stores and the request admission lanes.

The router registers authority, budget, receipt/report, federation,
certification, passport, fiscal, finding, health, and metrics handlers.
The service defaults to a 1 MiB body limit. Route overrides include 64 MiB
evidence imports, 128 MiB receipt appends, and 384 MiB admission-authority
requests. The service also applies concurrency and connection controls.
The generic request timeout is disabled to preserve budget quorum-wait rollback;
peer calls and shutdown have separate bounds. Shutdown drains requests, shares
one deadline with the cluster-loop join, stops payload maintenance and snapshots,
and flushes the receipt writer off async workers.

## Trust and invariants

`TrustServiceConfig::validate` rejects malformed or overlapping privileged
secrets, aliased database paths, simultaneous seed and SQLite capability custody,
and invalid replication issue skew. Joint authority replaces separate budget
and revocation databases and rejects peer cluster replication.
Keyring custody requires receipts, separate receipt anchors, and a workload
token; clustered keyring issuance is rejected. A configured fiscal runtime
requires joint authority and validated anchor/admission parameters.

`configure_receipt_store` rejects SQLite memory URI spellings as durable state
and checks checkpoint-related web3 prerequisites after attachment. It waits up
to 30 seconds for the local writer. Service receipt startup has its own behavior:
a writer still verifying healthy history can remain seeding after its readiness
wait; a failed seed refuses startup.

`DurableAdmissionRuntime::open` rejects memory databases and calls SQLite's
platform-support check. Serving currently requires Unix filesystem identity
and positioned I/O support. `attach` checks the kernel signing identity before
installing the shared mutation fence. Losing the seed cannot silently rebind
existing admission state to a replacement signing key.

`validate_service_auth` compares bearer material with `ConstantTimeEq`.
Read handlers can resolve an admin or tenant-scoped principal. Public routes
have individual authorization contracts. Authority inspection uses eight
non-queued permits held by blocking workers through cancellation; health uses
an independent one-permit lane and never provisions authority storage.
Configured unavailable authority produces HTTP 503 health with `ok: false`.
An unconfigured authority can report available without advertising signing keys.

Cluster state requires an out-of-band anchor when a capability authority
database is configured. Leader selection ranks observed signing custody and
then URLs; serving admission also requires current quorum and authenticated
history. Followers require an exact admitted leader envelope confirmed in the
current process and term. Reads recheck authority and cluster context.
Future issue skew defaults to zero and can be configured from 0 to 60 seconds;
expiry and local clock floors remain strict. Peer synchronization propagates stores through deltas/snapshots.

`FindingMarketConfig::validate` checks canonical non-weak Ed25519 role keys,
disjoint authority roles and pools, validity windows, status service-bond
bindings, finality requirements, and pinned fee-schedule operators.
`serve_with_finding_market_runtime` checks challenge configuration and shared
purchase/challenge mutation fences. The operator and purchase variants verify
the injected authority's database path. Startup requires a purchase executor
to have an idempotent rail and authority-status resolver. An authenticated
purchase with market/store configured but no executor returns HTTP 503.

`MarketFindingPurchaseVerifier` separates pure signed-carrier verification from
admission-time checks against current constituent bounds and an authoritative
reservation reader. Its construction and installation belong to the embedding
runtime. `reconcile_fiscal_runtime_startup` compares stored genesis and installed
adapter registry with anchored recovery and persisted readiness.

## Dependencies

`chio-kernel` provides execution, authority, admission, and store interfaces;
its `finding-market` feature is always enabled by this manifest.
`chio-store-sqlite` implements local durable authority and receipt ownership.
`chio-policy`, `chio-guards`, `chio-data-guards`, and `chio-external-guards`
provide policy compilation and guard implementations. `chio-core` supplies
signed protocol artifacts and canonical JSON; finding verification and market
crates supply the signed-carrier checks used by finding adapters.

Axum and Tokio host handlers and runtime tasks. `chio-http-serve` supplies
transport policy, listener limits, and drain support. Ureq implements the
synchronous trust client with a fixed timeout and redirects disabled. The economic,
fiscal, and FROST anchor transports dispatch through the `BlockingContractAgent` of
`chio-egress-contract`. `subtle` supplies secret
comparison. The crate's `pq` feature forwards to core, kernel,
and SQLite; `fuzz` exposes the Unix response-authority protocol fuzz boundary.

## Verification

`src/lib.rs` tests durable receipt URI refusal, web3 prerequisites, default and
configured guard installation, shared durable admission ownership, and lost
signing-seed rejection. Policy tests exercise invalid guard configuration,
runtime identity, default capabilities, and unsafe admission settings.
Service client tests exercise endpoint/token validation and bounded remote
receipt writes. Router tests cover authentication before admission body reads,
metrics authentication, and unconfigured fiscal refusal.

Unix finding integration tests exercise publication, discovery, purchase,
challenge enforcement, and status retraction through composed SQLite/router
seams. Their evidence helper leaves runtime-attestation, appraisal, attestation
trust, status-operator authorization, and status-freshness options unset.
Those fixtures do not establish acceptance of deployments requiring those
additional verifier inputs. Operators supply and validate their own trust roots,
executor installation, rails, authority custody, and transport configuration.

Run `cargo test -p chio-control-plane` for the package tests and
`cargo test -p chio-control-plane --doc` for instrumented library examples.
The README example uses a private temporary Unix directory and existing
`tempfile` development dependency, with default Cargo features and no services.
