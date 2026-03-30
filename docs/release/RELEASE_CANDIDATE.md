# ARC Release Candidate Surface

This document defines the supported ARC production-candidate surface for this
repository, including the completed `v2.8` launch-closure work plus the
locally verified `v2.9` economic-interop, `v2.10` underwriting,
`v2.11` portable-credential interop, `v2.12` workload-identity and
attestation, `v2.13` portable-credential lifecycle additions, `v2.14`
verifier-side OID4VP additions, `v2.15` multi-cloud attestation appraisal
additions, and `v2.16` enterprise-IAM profile additions, plus the `v2.17`
governed public certification-marketplace surface, the `v2.18` credit,
exposure, and capital-policy surface, the `v2.19` bonded-autonomy surface,
the `v2.20` liability-market surface, the `v2.21` standards-native
authorization and credential-fabric surface, and the `v2.22` wallet
exchange, identity-assertion, and sender-constrained authorization surface.

It is intentionally limited to behavior backed by the current codebase,
qualification scripts, and release docs.

## Launch Decision Contract

Promotion from "qualified candidate" to an externally published ARC launch
requires three gate classes:

- local evidence gates: `./scripts/ci-workspace.sh`,
  `./scripts/check-sdk-parity.sh`, and `./scripts/qualify-release.sh` must all
  pass, and the release docs must be updated together
- hosted publication gates: GitHub `CI` and `Release Qualification` workflows
  must be green on the exact candidate commit
- operator decision gates: release tag and package publication must be
  explicitly approved after the hosted gates are observed

## Current Decision Status

As of `2026-03-30`, the local evidence gates are satisfied for the current ARC
candidate, including the underwriting surfaces added in `v2.10`, the
portable-credential interop surfaces added in `v2.11`, the workload-identity
and trusted-verifier surfaces added in `v2.12`, and the standards-native
portable lifecycle surfaces added in `v2.13`, the verifier-side OID4VP bridge
added in `v2.14`, plus the multi-cloud appraisal surface added in `v2.15` and
the enterprise-IAM profile surface added in `v2.16`, plus the governed public
certification-marketplace surface added in `v2.17`, plus the credit backtest
and provider-risk-package surface added in `v2.18`, plus the bonded-execution
simulation and operator-control surface added in `v2.19`, plus the curated
liability-provider, quote/bind, claim/dispute/adjudication, and
marketplace-proof surface added in `v2.20`, plus the standards-native
portable claim/binding, multi-format credential, and hosted request-time
authorization surface added in `v2.21`, plus the wallet exchange, identity
continuity, and sender-constrained authorization surface added in `v2.22`.
External tag/publication remains on hold until the hosted workflow results are
observed.

## Supported Guarantees

- capability-scoped mediation remains the root trust contract for local,
  wrapped, and hosted runtime surfaces
- allow, deny, cancelled, and incomplete outcomes always produce signed
  receipts
- governed transaction approvals, x402, ACP/shared-payment-token commerce, and
  settlement reconciliation preserve truthful execution-versus-payment
  semantics instead of collapsing them into one status bit
- governed receipts can be projected into external authorization-details and
  delegated transaction-context reports derived from signed receipt metadata
  instead of operator-authored side documents
- ARC now ships machine-readable authorization-profile metadata and
  reviewer-pack evidence artifacts so enterprise IAM teams can inspect the
  supported profile, discovery boundary, and one governed action end to end
  without reverse-engineering ARC internals
- ARC now also ships one bounded hosted request-time authorization contract
  over the same profile, including explicit `authorization_details` and
  `arc_transaction_context` parameters, protected-resource/resource-indicator
  convergence, and fail-closed runtime-versus-audit artifact boundaries
- non-rail metered billing evidence stays operator-reconcilable through
  explicit sidecar state without mutating signed receipt truth
- trust-control centralizes authority, revocation, receipt, budget,
  certification, and federation state for supported operator deployments
- hosted remote sessions expose documented lifecycle and admin diagnostics
  through `/admin/health`, `/admin/sessions`, and session trust detail
- enterprise-provider and verifier-policy state is operator-visible through
  trust-control health and registry surfaces
- portable trust ships as `did:arc`, ARC-primary passport and verifier-policy
  schemas, challenge/response presentation, evidence export/import, and
  parent-bound federated delegation continuation, with legacy `arc.*`
  artifacts still accepted
- ARC now ships one qualified portable credential family over
  OID4VCI-compatible issuer metadata, with a native `AgentPassport` response,
  projected `application/dc+sd-jwt` and `jwt_vc_json` responses, portable
  issuer `JWKS`, portable type metadata, and operator-scoped lifecycle
  distribution and public resolution semantics over the same passport truth
- ARC now ships one qualified verifier-side OID4VP bridge over that portable
  credential lane, with signed `request_uri` request objects, one
  transport-neutral wallet exchange descriptor and canonical transaction
  state, one optional verifier-scoped identity assertion continuity lane,
  same-device and cross-device launch artifacts, ARC verifier metadata,
  verifier `JWKS`, and `direct_post.jwt` response verification, plus the
  existing public ARC-native challenge fetch and response submit routes
- ARC now also ships one bounded hosted sender-constrained continuation
  contract over that verifier/auth surface, with DPoP, mTLS thumbprint
  binding, and one attestation-confirmation profile that never widens runtime
  authority from attestation alone
- the insurer-facing behavioral feed exports signed decision, settlement,
  governed-action, and scoped reputation evidence from canonical ARC state
- ARC now ships signed underwriting policy inputs, deterministic
  underwriting-decision reports, persisted signed underwriting decisions, and
  explicit appeal records without mutating canonical receipt truth, including
  fail-closed issue validation, evidence-linked findings, and currency-safe
  premium handling
- ARC now ships non-mutating underwriting simulation so operators can compare
  baseline versus proposed policy outcomes over one canonical evidence package
- ARC now ships signed exposure-ledger and credit-scorecard exports, bounded
  facility-policy evaluation plus signed facility artifacts, deterministic
  credit backtests over historical windows, and signed provider-facing risk
  packages suitable for external capital review
- ARC now ships one non-mutating bonded-execution simulation lane so
  operators can compare baseline reserve-backed execution versus an explicit
  control policy with kill-switch and clamp-down semantics over the same bond
  and loss-lifecycle evidence
- ARC now ships one curated liability-provider registry with signed provider
  policy artifacts, supersession-aware publication, and fail-closed
  jurisdiction, coverage-class, currency, and evidence-requirement resolution
  before quote, placement, or claims state can be accepted
- ARC now also ships provider-neutral liability quote-request,
  quote-response, placement, and bound-coverage artifacts over one signed
  provider-risk package, with fail-closed stale-provider, quote-expiry,
  placement-mismatch, and unsupported-policy handling
- ARC now also ships immutable liability claim-package, provider-response,
  dispute, and adjudication artifacts linked back to bound coverage,
  exposure, bond, loss, and receipt evidence, with fail-closed oversized-claim
  and invalid-dispute handling
- ARC now locally qualifies that liability-market surface end to end across
  curated provider resolution, quote-and-bind, and claim/dispute lifecycle
  evidence, with release and partner materials updated to keep the marketplace
  claim bounded and honest
- runtime assurance is a first-class issuance and governed-execution input,
  with explicit assurance tiers and minimum-runtime-assurance constraints on
  economically sensitive grants
- workload identity and concrete attestation trust now ship with one typed
  SPIFFE-derived mapping contract, one canonical runtime-attestation
  appraisal contract, concrete Azure Attestation, AWS Nitro, and Google
  Confidential VM verifier bridges, and explicit trusted-verifier rebinding
  rules that fail closed on stale or unmatched evidence
- operators can export one signed runtime-attestation appraisal report from
  local state or trust-control so verifier family, normalized assertions,
  vendor-scoped claims, and policy-visible outcomes are exchangeable without
  re-querying the verifier path
- launch claims are bounded by executable diff-tests, runtime/integration
  verification, and release qualification; standalone Lean proof files are not
  part of the shipped release gate while they remain outside the root import
  surface or contain `sorry`
- `ARC Certify` ships as a signed operator evidence artifact plus a
  fail-closed registry with `active`, `superseded`, `revoked`, and `not-found`
  resolution states
- portable passport lifecycle discovery now requires explicit TTL-backed
  public status distribution and exposes fail-closed `stale` resolution state
  instead of treating over-aged lifecycle truth as implicitly current
- `ARC Certify` now also ships one governed public discovery surface with
  versioned evidence profiles, public publisher metadata, public search and
  transparency feeds, explicit dispute state, and policy-bound consume flows
  that do not widen runtime trust from listing visibility alone
- the A2A adapter covers the current shipped matrix of discovery, blocking and
  streaming message execution, follow-up task management, push-notification
  config CRUD, durable task correlation, and fail-closed auth negotiation
- the TypeScript, Python, and Go SDKs are release-qualified against the
  supported HTTP/session surface rather than treated as unverified examples

## Supported Defaults And Limits

| Limit or default | Value | Source |
| --- | --- | --- |
| default max capability TTL | `3600s` | `crates/arc-cli/src/policy.rs` |
| default delegation depth | `5` | `crates/arc-cli/src/policy.rs` |
| default streamed tool duration limit | `300s` | `crates/arc-kernel/src/lib.rs` |
| default streamed tool total-byte limit | `256 MiB` | `crates/arc-kernel/src/lib.rs` |
| default MCP page size | `50` | `crates/arc-mcp-adapter/src/edge.rs` |
| background-task progression per edge tick | `8 tasks` | `crates/arc-mcp-adapter/src/edge.rs`, `crates/arc-mcp-adapter/src/transport.rs` |
| remote session idle expiry | `15 min` | `crates/arc-cli/src/remote_mcp.rs` |
| remote session drain grace | `5 s` | `crates/arc-cli/src/remote_mcp.rs` |
| remote session tombstone retention | `30 min` | `crates/arc-cli/src/remote_mcp.rs` |

Release qualification depends on those defaults being covered by tests and on
stricter user-provided values continuing to fail closed.

## Explicit Non-Goals

The current ARC candidate does not claim:

- multi-region or consensus trust replication
- a permissionless or auto-trusting public certification marketplace
- automatic SCIM provisioning lifecycle
- synthetic cross-issuer passport trust aggregation
- generic sender-constrained interoperability or attestation-only sender
  authorization beyond ARC's documented DPoP, mTLS, and paired
  attestation-confirmation profile
- generic attestation-result interoperability beyond ARC's documented
  canonical appraisal contract and concrete Azure, AWS Nitro, or Google
  verifier bridges
- liability-market capital allocation or autonomous insurer pricing beyond the
  documented underwriting policy surface
- automatic claims payment, external recovery clearing, or insurer-network
  messaging beyond ARC's documented liability-market orchestration boundary
- full theorem-prover completion for all protocol claims
- performance-first throughput tuning beyond the documented qualification lane

## Migration Story

- existing wrapped MCP servers can be hosted through `arc mcp serve` and
  `arc mcp serve-http`
- trust-control-backed deployments can centralize authority, revocation,
  receipts, budgets, federation registries, and certification state through
  `arc trust serve`
- new policy work should start from
  `examples/policies/canonical-hushspec.yaml`
- existing deployments may keep using legacy PACT YAML as a compatibility input
- ARC-branded schema issuance is now primary, while legacy `arc.*` artifacts
  remain verifiable/importable
- `did:arc` remains the currently shipped canonical DID method
- portable trust and cross-org workflows start from
  [AGENT_PASSPORT_GUIDE.md](../AGENT_PASSPORT_GUIDE.md) and
  [IDENTITY_FEDERATION_GUIDE.md](../IDENTITY_FEDERATION_GUIDE.md)
- A2A integrations start from [A2A_ADAPTER_GUIDE.md](../A2A_ADAPTER_GUIDE.md)

## Operator And Release Guidance

- use `./scripts/ci-workspace.sh` for routine validation
- use `./scripts/qualify-release.sh` before treating a branch as a production
  candidate
- use [QUALIFICATION.md](QUALIFICATION.md) as the release-proof matrix
- use [ECONOMIC_INTEROP_GUIDE.md](../ECONOMIC_INTEROP_GUIDE.md) when IAM,
  finance, or partner reviewers need the focused economic-context walkthrough
- use `arc trust credit-backtest export` and
  `arc trust provider-risk-package export` when capital reviewers need replay
  evidence or one signed provider-facing credit package
- use [CREDENTIAL_INTEROP_GUIDE.md](../CREDENTIAL_INTEROP_GUIDE.md) when a
  verifier, wallet, or standards reviewer needs the focused portable
  credential interop boundary, portable lifecycle semantics, and raw-HTTP
  proof lane
- use `arc trust appraisal export` when an operator needs one signed
  multi-cloud runtime-attestation appraisal artifact for review or partner
  exchange
- use `arc trust underwriting-decision simulate` when an operator needs to
  inspect policy deltas before issuing a new signed underwriting decision
- use [PARTNER_PROOF.md](PARTNER_PROOF.md) when a partner, insurer, or
  standards reviewer needs the compact evidence package instead of raw build
  logs
- use [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) and
  [OBSERVABILITY.md](OBSERVABILITY.md) for deployment and incident response
- use [RELEASE_AUDIT.md](RELEASE_AUDIT.md), [GA_CHECKLIST.md](GA_CHECKLIST.md),
  and [RISK_REGISTER.md](RISK_REGISTER.md) as the go/no-go record instead of
  relying on tribal knowledge
- do not tag from local evidence alone; hosted workflow observation is still a
  required publication gate
