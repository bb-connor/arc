# Release Candidate Surface

This document defines the supported `v2.3` production-candidate surface for
this repository.

It is intentionally limited to behavior backed by the current codebase,
qualification scripts, and release docs.

## Supported Guarantees

- capability-scoped mediation remains the root trust contract for local,
  wrapped, and hosted runtime surfaces
- allow, deny, cancelled, and incomplete outcomes always produce signed
  receipts
- trust-control centralizes authority, revocation, receipt, budget,
  certification, and federation state for supported operator deployments
- hosted remote sessions expose documented lifecycle and admin diagnostics
  through `/admin/health`, `/admin/sessions`, and session trust detail
- enterprise-provider and verifier-policy state is operator-visible through
  trust-control health and registry surfaces
- portable trust ships as `did:pact`, Agent Passport, signed verifier-policy
  artifacts, challenge/response presentation, evidence export/import, and
  parent-bound federated delegation continuation
- `PACT Certify` ships as a signed operator evidence artifact plus a
  fail-closed registry with `active`, `superseded`, `revoked`, and `not-found`
  resolution states
- the A2A adapter covers the current shipped matrix of discovery, blocking and
  streaming message execution, follow-up task management, push-notification
  config CRUD, durable task correlation, and fail-closed auth negotiation
- the TypeScript, Python, and Go SDKs are release-qualified against the
  supported HTTP/session surface rather than treated as unverified examples

## Supported Defaults And Limits

| Limit or default | Value | Source |
| --- | --- | --- |
| default max capability TTL | `3600s` | `crates/pact-cli/src/policy.rs` |
| default delegation depth | `5` | `crates/pact-cli/src/policy.rs` |
| default streamed tool duration limit | `300s` | `crates/pact-kernel/src/lib.rs` |
| default streamed tool total-byte limit | `256 MiB` | `crates/pact-kernel/src/lib.rs` |
| default MCP page size | `50` | `crates/pact-mcp-adapter/src/edge.rs` |
| background-task progression per edge tick | `8 tasks` | `crates/pact-mcp-adapter/src/edge.rs`, `crates/pact-mcp-adapter/src/transport.rs` |
| remote session idle expiry | `15 min` | `crates/pact-cli/src/remote_mcp.rs` |
| remote session drain grace | `5 s` | `crates/pact-cli/src/remote_mcp.rs` |
| remote session tombstone retention | `30 min` | `crates/pact-cli/src/remote_mcp.rs` |

Release qualification depends on those defaults being covered by tests and on
stricter user-provided values continuing to fail closed.

## Explicit Non-Goals

The `v2.3` release candidate does not claim:

- multi-region or consensus trust replication
- a public certification marketplace
- automatic SCIM provisioning lifecycle
- synthetic cross-issuer passport trust aggregation
- full theorem-prover completion for all protocol claims
- performance-first throughput tuning beyond the documented qualification lane

## Migration Story

- existing wrapped MCP servers can be hosted through `pact mcp serve` and
  `pact mcp serve-http`
- trust-control-backed deployments can centralize authority, revocation,
  receipts, budgets, federation registries, and certification state through
  `pact trust serve`
- new policy work should start from
  `examples/policies/canonical-hushspec.yaml`
- existing deployments may keep using legacy PACT YAML as a compatibility input
- portable trust and cross-org workflows start from
  [AGENT_PASSPORT_GUIDE.md](../AGENT_PASSPORT_GUIDE.md) and
  [IDENTITY_FEDERATION_GUIDE.md](../IDENTITY_FEDERATION_GUIDE.md)
- A2A integrations start from [A2A_ADAPTER_GUIDE.md](../A2A_ADAPTER_GUIDE.md)

## Operator And Release Guidance

- use `./scripts/ci-workspace.sh` for routine validation
- use `./scripts/qualify-release.sh` before treating a branch as a production
  candidate
- use [QUALIFICATION.md](QUALIFICATION.md) as the release-proof matrix
- use [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) and
  [OBSERVABILITY.md](OBSERVABILITY.md) for deployment and incident response
- use [RELEASE_AUDIT.md](RELEASE_AUDIT.md), [GA_CHECKLIST.md](GA_CHECKLIST.md),
  and [RISK_REGISTER.md](RISK_REGISTER.md) as the go/no-go record instead of
  relying on tribal knowledge
