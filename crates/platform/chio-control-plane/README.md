# chio-control-plane

Runtime wiring for Chio deployments. The crate assembles a
`chio_kernel::ChioKernel` from policy and local or remote stores, and provides
the clustered trust-control HTTP service used to share capability authority,
budget, receipt, and revocation state.

This is a supported integration surface. `chio-cli`, `chio-wall`, and
`chio-mercury` build binaries on it, while hosted and remote protocol adapters
reuse its error and identity-provider types.

## Responsibilities

- Build a kernel from `LoadedPolicy` and attach local SQLite or remote receipt,
  revocation, budget, and capability-authority stores.
- Load plain YAML or HushSpec policy into guard pipelines and default
  capabilities.
- Gate capability issuance on reputation and runtime-attestation evidence.
- Verify Azure MAA, AWS Nitro, Google Confidential VM, and signed enterprise
  verifier attestations.
- Host capability, budget, revocation, receipt, evidence, passport,
  certification, credit, capital, liability, and underwriting endpoints.
- Replicate authority state across authenticated trust-control cluster members.
- Export and import signed evidence bundles across tenants and federation
  partners.
- Certify tool-server conformance and publish certifications through a
  federated marketplace.
- Map SCIM and enterprise identity-provider records onto Chio identity context.
- Bind portable transaction passports to signed risk-comptroller evidence.
- Expose the seller rail used by governed commerce flows.

## Cluster boundary

Cluster traffic uses dedicated per-node Ed25519 membership identities. Each
node requires a strict private seed, an exact normalized URL-to-public-key
membership map, and a durable replay database. Internal routes reject general
service and administrative bearers. Membership proves transport origin only;
privileged authority operations still require the workload or administrator
role configured for that operation.

## Dashboard read boundary

The browser dashboard does not receive a service, administrator, workload,
tenant, cluster, or relay bearer. Configure a distinct
`CHIO_TRUST_DASHBOARD_READ_TOKEN`; the browser submits it once to
`POST /v1/dashboard/session` and receives a short-lived, host-only,
`HttpOnly` session cookie. Sessions are bounded in memory, expire after 15
minutes, and become invalid after a trust-control restart.

The session is accepted only by receipt query, receipt analytics, operator
report, lineage, agent receipt, reputation comparison, and relay observability
read surfaces. It is not accepted by mutation, administrative, signing,
issuance, revocation, budget-write, cluster, or evidence-export endpoints.

Relay observability is optional. Configure both
`CHIO_TRUST_DASHBOARD_REPORT_ORIGIN` and
`CHIO_TRUST_DASHBOARD_REPORT_TOKEN` to proxy the relay's live
`GET /v1/chio/pheromone/observability` endpoint. The origin must use HTTPS;
HTTP is limited to explicit loopback test mode. The relay token must be
distinct from every other credential. Generated alert and assurance report
files are not exposed as live trust-control routes.

## Public API

- `CliError` provides the shared CLI and service error vocabulary and converts
  to `StructuredErrorReport`.
- `build_kernel` installs default and policy guard pipelines and
  post-invocation hooks.
- `configure_receipt_store`, `configure_revocation_store`,
  `configure_capability_authority`, and `configure_budget_store` attach local
  or remote state.
- `load_or_create_authority_keypair`, `rotate_authority_keypair`, and
  `authority_public_key_from_seed_file` manage authority seed files.
- `JwtProviderProfile` selects generic, Auth0, Okta, or Azure AD identity
  handling.

The top-level modules are `attestation`, `certify`, `enterprise_federation`,
`evidence_export`, `federation_policy`, `issuance`, `passport_verifier`,
`policy`, `reputation`, `scim_lifecycle`, `security`, `seller_rail`,
`transaction_passport_risk`, and `trust_control`.

Facade re-exports provide agent-web interoperability, commerce orders,
enterprise export, risk comptroller, transaction passports, and trust-market
context.

## Feature flags

The `pq` flag enables post-quantum signing in the core, kernel, and SQLite
store layers.

## Testing

Run `cargo test -p chio-control-plane`. Integration tests exercise facade
re-exports and web3 anchor qualification. Cluster and report endpoint
regressions live under `trust_control/cluster_and_reports`.
