# chio-control-plane

Runtime-wiring layer for a Chio deployment. `lib.rs` assembles a
`chio_kernel::ChioKernel` from a loaded policy and a set of local or remote
stores; `trust_control` separately implements the clustered trust-control HTTP
service (and its client) that lets multiple Chio nodes share capability
authority, budget, receipt, and revocation state. The crate defines no
protocol types of its own - it composes `chio-kernel` with `chio-store-sqlite`,
`chio-guards`, `chio-policy`, `chio-credentials`, `chio-reputation`, and the
economic/trust domain crates behind about a dozen subsystem modules.

`[package.metadata.chio] public_entrypoint = true`: this is a supported
integration surface. `chio-cli`, `chio-wall`, and `chio-mercury` build their
`chio` binaries on it; `chio-mcp-remote` and `chio-hosted-mcp` re-export its
`CliError` and `JwtProviderProfile`.

Signed authority replication defaults to zero future issue skew. Operators
with a measured receiver clock lag can explicitly set
`chio trust serve --authority-replication-max-future-skew-seconds 1`
(or `TrustServiceConfig::authority_replication_max_future_skew_seconds`). The
configured bound is 0 to 60 seconds. It applies only to signed envelope issue
times, never to expiry, local clock regression or issuer activation deadlines.
Followers refuse authority verification reads when their authenticated
envelope expires or an authority import from the elected leader is unresolved.
The successful import must belong to the current process and the current
election term; restart, leader changes and failed synchronization require
another authenticated import before a follower serves issuer trust.
Clustered trust reads also require current quorum. The elected leader needs
live signing custody of its authenticated head and enough authenticated peer
chain agreements observed in its current term to reach quorum. Each agreement
binds the configured peer's advertised self URL before and after its envelope;
an alias for one logical node cannot supply another authority vote. Key possession
and URL election alone cannot authorize a returning former custodian. Known
authenticated newer or conflicting history prevents old-head serving even if
its import refuses replay or that peer later becomes unreachable. A peer with
an authority error contributes no agreement; a fresh signed majority can still
admit the leader after a minority's transport failure.
Refused signed-history evidence retains the maximal authenticated chain within
the existing chain limit. A shorter valid relay cannot erase that witness or
create a conflict. Truly incomparable signed histories remain a serving refusal
for the process, even if a later import encompasses one branch.
Followers require an elected source that itself admits the imported state
under stable source leader, quorum and term samples. Internal signed exports
remain available for convergence before either node can serve, allowing a
leader to observe signed peer agreement before followers confirm its status.
Nonleader relays authenticate history but cannot overwrite a follower's
leader-confirmed envelope; inspection of a consistent prefix does not relax
the replay rules of an actual import.
Confirmation binds the exact imported signed envelope, including its issue and
expiry times and signature. Locally re-signing an old head cannot renew that
confirmation. Reads recheck leader, term, quorum and the exact admitted view
before return. Public trust documents and verification use that same view
throughout construction. A signing operation binds its actual artifact key to
the admitted live head and rechecks admission before returning the artifact.
Public JWKS, verifier metadata/discovery and OID4VP issuer verification use
the same freshness contract and the bounded public passport admission lane.
Those authority document routes return HTTP 503 when a configured SQLite
authority cannot pass admission, including absent storage, clock regression or
unsafe file custody. Generic-market listings require their discovery signer to
own the locally inspected live authority head and can refuse with HTTP 409 on
followers. Cluster-wide authority admission for those listings remains follow-up
work. Missing plain-seed authority routes retain their existing refusal statuses.
With no authority configured, issuer
metadata remains unsigned with no portable signing key or JWKS; discovery and
JWKS refuse with 404, and OID4VP trust reads refuse with 409.
Unconfigured health returns 200 with `configured: false` and `available: true`
for a successful inspection, while publishing no backend or key material.
Health then reports unavailable authority with HTTP 503 and degraded peer
counts; independent revocation and budget replication continue. An admitted
leader or a confirmed import from that leader restores authority readiness.
Authenticated authority inspections use a separate eight-permit, non-queued
blocking lane. Cancellation retains admission until the worker completes.
Owner provisioning, mutation fences and SQLite issuance use the service clock
and configured receiver policy, preserving local clock regression refusal.
Explicit service startup provisions a configured plain signing seed through
the owner custody loader. Requests load it only if it still exists; losing
that seed causes refusal and never creates replacement custody. Keyring-owned
seeds remain under keyring initialization and are not provisioned by this path.
Health also returns HTTP 503 when configured authority storage is absent or
unreadable. Its independent single-permit inspection lane never provisions
authority storage or occupies authenticated request admission; a cancelled
request retains its permit until the blocking inspection finishes.

## Responsibilities

- Build a `ChioKernel` from a `LoadedPolicy` and wire local (SQLite) or remote
  (`--control-url`) receipt, revocation, budget, and capability-authority
  stores (`build_kernel`, `configure_receipt_store`,
  `configure_revocation_store`, `configure_capability_authority`,
  `configure_budget_store`).
- Load Chio policy files (plain YAML or HushSpec) into a guard pipeline and a
  default capability set (`policy`).
- Gate capability issuance on reputation tier and runtime-attestation tier,
  narrowing the granted scope of economically sensitive grants (`issuance`).
- Verify runtime attestation evidence from Azure MAA, AWS Nitro, Google
  Confidential VM, and a signed generic "enterprise verifier" format
  (`attestation`).
- Host the trust-control HTTP service - capability authority, budget,
  revocation, receipts, evidence export, OID4VCI/OID4VP passports,
  certification marketplace, and credit/capital/liability/underwriting
  endpoints - and its HTTP client (`trust_control`).
- Replicate authority, budget, receipt, and revocation state across a cluster
  of trust-control nodes (`trust_control::cluster`).
- Export and import signed evidence bundles across tenants and federation
  partners (`evidence_export`, `federation_policy`).
- Certify MCP tool-server conformance and publish or discover certifications
  across a federated marketplace (`certify`).
- Map SCIM and enterprise IdP identities (OIDC, OAuth introspection, SAML)
  onto Chio enterprise identity context (`scim_lifecycle`,
  `enterprise_federation`).
- Verify OID4VCI/OID4VP portable passports and bind a `TransactionPassport` to
  its signed risk-comptroller evidence (`passport_verifier`,
  `transaction_passport_risk`).

## Public API

`src/lib.rs`:

- `CliError` - the unified error type for every CLI and service code path;
  `.report()` converts it to a `StructuredErrorReport`, mapping most
  subsystem errors onto `chio_errors` registry codes.
- `build_kernel(LoadedPolicy, &Keypair) -> ChioKernel` - installs the default
  and policy guard pipelines and post-invocation hooks.
- `configure_receipt_store` / `configure_revocation_store` /
  `configure_capability_authority` / `configure_budget_store` - attach a local
  SQLite store, a remote store built from `--control-url`, or (for the
  capability authority) a reputation/attestation-gated wrapper.
- `load_or_create_authority_keypair`, `rotate_authority_keypair`,
  `authority_public_key_from_seed_file` - authority seed-file lifecycle.
- `JwtProviderProfile` - enterprise JWT provider profile (`Generic`, `Auth0`,
  `Okta`, `AzureAd`).

Top-level modules:

| Module | Owns |
|---|---|
| `policy` | Policy loading (`load_policy`), guard pipeline construction, default capabilities |
| `issuance` | `wrap_capability_authority`: reputation- and attestation-gated capability issuance |
| `attestation` | Runtime attestation verifier adapters and their appraisal |
| `trust_control` | The trust-control HTTP service, client, and cluster replication - see [ARCHITECTURE.md](./ARCHITECTURE.md) for its own module map |
| `certify` | MCP conformance certification, local registry, federated marketplace |
| `evidence_export` | Signed evidence bundle export/import |
| `federation_policy` | Permissionless federation open-admission policy registry |
| `passport_verifier` | OID4VCI/OID4VP stores and the portable-passport lifecycle registry |
| `enterprise_federation` | Enterprise IdP and certification-discovery-network registries |
| `scim_lifecycle` | SCIM user provisioning mapped to Chio identity |
| `reputation` | CLI commands for local reputation inspection and passport comparison |
| `transaction_passport_risk` | Binds a transaction passport to its signed risk-comptroller report |

Re-exported facade crates: `agent_web` (`chio-agent-web-interop`),
`enterprise_export` (`chio-enterprise-export`), `risk_comptroller`
(`chio-risk-comptroller`), `commerce_order` (`chio-commerce-order`),
`transaction_passport` (`chio-transaction-passport`), `trust_market`
(`chio-trust-market-context`).

## Prepared flow dispatch

`security::adapters::PersistentFlowResolver::prepare_dispatch` returns an opaque,
one-shot `PreparedFlowDispatch` tied to that resolver's immutable manifest and
policy configuration. Preparation validates and classifies without consuming a
declassification grant, joining flow state, acquiring a fence or emitting a
receipt. Dropping the plan has no such effects. Its consuming `commit` method
rechecks the exact current flow snapshot, grant/fence deadlines and the original
authority's clock, then follows the existing attested consumption and outcome
path. It cannot accept replacement inputs, stores or a different resolver.

The plan borrows its original request and exposes `live_request_digest`, a
commitment to the complete canonical envelope including transient credentials.
`validate_live_request` checks a candidate against that commitment; commit also
rechecks the borrowed request before mutation. This is not authentication or
operation-owned custody. The existing flow/declassification request hash binds
only the canonical argument payload and remains unchanged. Neither hash can
replace the other, or the credential-stripped original admission material hash.

The existing `commit_dispatch` entry point uses this same preparation path.
Preparation is not operation-owned security custody or an external execution
permit. Flow, declassification and receipt stores retain their existing separate
transactions; full joined custody and crash recovery remain required.

## Native input and post-join flow policy

`security::adapters::NativeFlowResolver` uses the same read-only verified-manifest
and classifier policy as the legacy resolver, but owns no legacy state backend.
As a `SecurityPreDispatchHook`, it validates admitted manifest/bridge metadata
and classifies the original canonical arguments before budget capture. It joins
classification plus the operator floor through `NativeSecurityFlowJoinAuthority::join_input`.
The kernel derives identity and intent; the fenced SQLite writer resolves every
inherited principal, lineage and session label and propagates the full source
in the operation's single join. No partial snapshot stands in for absent state.

It consumes `PreparedNativeSecurityEgress` from the kernel, classifies that
handle's borrowed request against its fresh native observation, and requires
the full computed taint to be covered by each already joined native label.
Insufficient propagation or changed classification denies without another join.

Its one-shot `PreparedNativeFlowDispatch::commit_custody` revalidates the
original operation and policy clock. Egress decisions acquire and commit native
custody; local non-egress decisions do not manufacture a fence. Callback panics,
clock failures, mismatched authority, legacy evidence-store configuration and
native declassification fail closed. The result is historical policy and
optional egress data, never an execution permit or credential disposition.

`policy_evidence()` exposes the exact canonical policy record produced during
that preparation: classifier evidence and category bindings, admitted policy and
manifest commitments, native observation, original/live request digests, decision
and deadline. The record is limited to 256 KiB and excludes argument payloads and
reusable credentials. Oversized evidence denies before egress acquisition. Its
bytes survive custody commitment unchanged; neither decoding nor retaining them
can substitute for the pending durable dispatch ledger and current credentials.
Classifier field paths, labels and other policy metadata may still be sensitive;
the canonical record is not intended for unredacted application logs.

The production before-budget hook and complete first join are implemented.
Dispatch-ledger/credential coupling,
native nonce/declassification, outcome recovery and activation remain required.
The real-kernel SQLite tests use the test-support checkpoint and retain the
unconditional native dispatch refusal.

## Feature flags

| Flag | Effect |
|------|--------|
| `pq` | Enables post-quantum signing via `chio-core/pq`, `chio-kernel/pq`, and `chio-store-sqlite/pq`. |

## Testing

`cargo test -p chio-control-plane`

Integration tests under `tests/` exercise the re-exported facade modules
(`agent_web`, `enterprise_export`, `transaction_passport`, `trust_market`) and
a web3 anchor-ops qualification path. `trust_control/cluster_and_reports.rs`
(`#[cfg(test)]`) holds cluster- and report-endpoint regression coverage,
backed by `proptest-regressions/`.

## See also

- `chio-kernel` - supplies `ChioKernel` and the store/authority traits this
  crate wires locally and re-implements remotely over HTTP.
- `chio-store-sqlite` - the local SQLite store implementations this crate
  opens.
- `chio-policy` - HushSpec parsing and compilation consumed by
  `policy::load_policy` (not the same thing as this crate's own `policy`
  module - watch for the name collision).
- `chio-guards`, `chio-data-guards`, `chio-external-guards` - guard
  implementations assembled by `policy::build_guard_pipeline`.
- `chio-credentials` - OID4VCI/OID4VP and passport primitives underlying
  `passport_verifier` and `trust_control`'s passport handlers.
- `chio-cli` - the primary consumer binary (`chio trust serve`,
  `--control-url`).
