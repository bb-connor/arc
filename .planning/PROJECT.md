# PACT

## What This Is

PACT (Provable Agent Capability Transport) is a protocol and trust-control
plane for secure, attested agent access to tools, resources, and cross-agent
workflows. It combines capability-based security, cryptographic receipts,
economic enforcement, portable trust credentials, and cross-org evidence
exchange so operators can prove what an agent was allowed to do, what it
actually did, and how that activity should be trusted across boundaries.

## Core Value

PACT must provide deterministic, least-privilege agent access with auditable
outcomes, and produce cryptographic proof artifacts (receipts) that enable
economic metering, regulatory compliance, and agent reputation.

## Current State

**Latest archived milestone:** v2.4 Architecture and Runtime Decomposition
(archived
2026-03-25)
**Archive:** `.planning/milestones/v2.4-ROADMAP.md`
**Audit:** `.planning/milestones/v2.4-MILESTONE-AUDIT.md`
**Active milestone:** none
**Next planned milestone:** v2.5 Commercial Trust Primitives

PACT has now closed the architecture decomposition wave as well. `v2.4` is
archived, which means the service, store, adapter, and domain boundaries are
substantially cleaner and the workspace now has executable layering checks for
the core domain crates. There is no active milestone at the moment. The next
planned wave is `v2.5`, but it should be activated deliberately so its
requirements reflect the post-refactor codebase instead of the pre-refactor
assumptions.

## Previous Milestone: v2.3 Production and Standards

**Goal:** Turn the broad product surface into a release-qualifiable,
maintainable, standards-aligned production candidate.

**Completed features:**
- Source-only release inputs and cleaner runtime ownership boundaries
- Canonical release qualification across workspace, dashboard, SDK, live
  conformance, and repeat-run trust-cluster proof
- Supported observability and health contracts for trust-control, hosted edges,
  federation, and A2A diagnostics
- Protocol spec v2 alignment, standards-submission draft artifacts, and launch
  readiness evidence

## Latest Completed Milestone: v2.4 Architecture and Runtime Decomposition

**Goal:** Convert the remaining oversized runtime crates into explicit service,
storage, edge, and domain boundaries while preserving shipped behavior and
keeping downstream breakage low.

**Completed features:**
- `pact-cli` becomes a thin command shell, with trust-control and hosted MCP
  runtime extracted into dedicated crates
- `pact-kernel` becomes an enforcement core again, with SQLite-backed stores,
  query/report logic, and export logic moved behind a dedicated persistence
  crate
- MCP edge/session runtime and A2A adapter internals are decomposed around real
  transport boundaries instead of single giant files
- Credentials, reputation, and policy internals are split into maintainable
  modules with dependency direction enforced across the workspace

**Execution order followed:**
- Extract service crates first, using compatibility facades so the CLI surface
  stays stable
- Move SQLite-backed persistence/query/report code out of `pact-kernel` once
  fewer public entrypoints depend on it
- Split MCP/A2A adapter boundaries after the runtime and kernel contracts are
  steadier
- Finish with domain-module cleanup and dependency enforcement before starting
  the next feature wave

## Next Planned Milestone: v2.5 Commercial Trust Primitives

**Goal:** Extend the productionized and restructured trust substrate into
commercial and insurer-facing primitives without building those surfaces on top
of architectural debt.

**Target features:**
- Insurer-facing behavioral feeds and export contracts
- Marketplace trust primitives layered on receipts, budgets, and portable trust
- Cross-org reputation and commercial trust distribution
- Payment-rail and settlement-adjacent integration planning

## Requirements

### Validated

- ✓ Capability-scoped mediation, guard evaluation, and signed receipts -- v1.0
- ✓ MCP-compatible tool, resource, prompt, completion, logging, roots,
  sampling, and elicitation flows -- v1.0
- ✓ Live conformance waves against JS and Python peers -- v1.0
- ✓ HA trust-control determinism and reliability -- v1.0
- ✓ Roots enforced as filesystem boundary -- v1.0
- ✓ Remote runtime lifecycle hardening -- v1.0
- ✓ Cross-transport task/stream/cancellation semantics -- v1.0
- ✓ Unified policy surface (HushSpec canonical, PACT YAML compat) -- v1.0
- ✓ Release qualification with conformance + repeat-run proof -- v1.0
- ✓ pact-core schema forward compatibility (deny_unknown_fields removed) -- v2.0
- ✓ Monetary budgets with single-currency enforcement -- v2.0
- ✓ Merkle-committed receipt batches with signed kernel checkpoints -- v2.0
- ✓ Velocity guard (synchronous token bucket rate limiting) -- v2.0
- ✓ DPoP proof-of-possession (PACT-native, Ed25519 canonical JSON) -- v2.0
- ✓ Receipt retention with time/size rotation and archived Merkle verification
  -- v2.0
- ✓ Colorado SB 24-205 compliance mapping document -- v2.0
- ✓ EU AI Act Article 19 compliance mapping document -- v2.0
- ✓ Receipt query API with 8-dimension filtering and cursor pagination -- v2.0
- ✓ TypeScript SDK 1.0 (`@pact-protocol/sdk`) with DPoP helpers -- v2.0
- ✓ SIEM exporters (Splunk HEC + Elasticsearch bulk) behind feature flag -- v2.0
- ✓ Capability lineage index with delegation chain tracking -- v2.0
- ✓ Receipt dashboard SPA with operator summaries, lineage, and portable
  comparison views -- v2.0
- ✓ Payment bridge substrate, truthful settlement model, and delegation-chain
  cost attribution -- post-v2.0
- ✓ Compliance evidence export and offline verification -- post-v2.0
- ✓ Python and Go SDKs moved to release-ready beta posture -- post-v2.0
- ✓ Local reputation scoring and reputation-gated issuance -- post-v2.0
- ✓ `did:pact`, Agent Passport alpha, challenge-bound presentation, and
  verifier evaluation -- post-v2.0
- ✓ A2A adapter alpha with streaming, task lifecycle, and broad auth-matrix
  support -- post-v2.0
- ✓ Identity federation alpha with OIDC/JWKS/introspection-backed stable
  subject derivation -- post-v2.0
- ✓ Bilateral evidence-sharing, federated evidence import, and multi-hop
  cross-org delegation -- post-v2.0
- ✓ Enterprise federation administration, provider-backed policy context, and
  operator-visible identity provenance -- v2.1
- ✓ Portable verifier policy artifacts and replay-safe verifier challenge
  handling -- v2.1
- ✓ Multi-issuer Agent Passport composition semantics and issuer-aware
  verification -- v2.1
- ✓ Shared remote evidence references and cross-org operator
  analytics/reporting -- v2.1
- ✓ Explicit A2A request shaping and fail-closed partner admission hardening --
  v2.2
- ✓ Durable restart-safe A2A task correlation and follow-up validation -- v2.2
- ✓ Registry-backed certification publication, resolution, and revocation --
  v2.2
- ✓ Operator-facing docs and regression coverage for the v2.2 A2A and
  certification surfaces -- v2.2

### Next Milestone Priorities

- [ ] Turn `v2.5` from an outline into a concrete requirement set and phased
  roadmap
- [ ] Decide whether the first commercial slice is insurer-facing feeds,
  marketplace trust primitives, or cross-org reputation distribution
- [ ] Preserve the new architecture guardrails while extending the commercial
  surface

## Out of Scope

- Commercial and insurer-facing trust primitives are not active yet -- `v2.5`
  is planned but not started
- Full public certification marketplace -- separate network/commercial problem
- Payment-rail settlement integration -- belongs in the commercial milestone
- Multi-region Byzantine consensus -- premature at the current trust-control
  scale
- Full OS sandbox manager -- different product layer

## Context

PACT is a Rust workspace with protocol, kernel, CLI, portable-credential,
reputation, A2A-adapter, SIEM, SDK, conformance, and formal surfaces. The
product surface is now broad and the release lane exists, but the codebase
still carries concentrated structural debt in a handful of oversized
entrypoints: `crates/pact-kernel/src/lib.rs`,
`crates/pact-mcp-edge/src/runtime.rs`, `crates/pact-cli/src/remote_mcp.rs`,
and `crates/pact-cli/src/trust_control.rs`. `v2.4` addressed the first major
architecture concentration wave. The next decision is which commercial surface
should be activated on top of the steadier workspace.

Key regulatory milestones achieved:
- Colorado SB 24-205 compliance document filed (deadline June 30, 2026)
- EU AI Act Article 19 compliance document filed (deadline August 2, 2026)

## Constraints

- **Tech stack**: Rust 2021 workspace, Rust 1.93 MSRV. `pact-siem` behind
  feature flag.
- **Compatibility**: v1.0, v2.0, v2.1, v2.2, v2.3, and v2.4 behavior must remain
  truthful unless intentionally versioned/documented.
- **Security**: Fail-closed behavior remains mandatory. Refactoring cannot
  widen trust or weaken attestation guarantees.
- **Operational quality**: `cargo fmt`, `cargo clippy`, `cargo test --workspace`
  remain hard gates, not advisory checks.
- **Execution system**: `.planning/` remains the active source of truth for
  milestone and phase execution.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| PACT stays separate from ClawdStrike | Protocol must be vendor-neutral for standards submissions | ✓ Maintained |
| Single currency first for monetary budgets | Multi-currency adds exchange-rate complexity | ✓ Shipped v2.0 |
| Port ClawdStrike code rather than rewrite | Production-tested code adapted faster | ✓ DPoP, velocity, SIEM ported |
| Scope v2.0 to Q2-Q3 2026 | Hit regulatory deadlines | ✓ Shipped ahead of deadlines |
| Merkle commitment parallelized with monetary budgets | Both small enough for Q2 | ✓ Shipped together in Phase 8 |
| A2A adapter deferred to Q4 | A2A v1.0 spec stability uncertain | ✓ Shipped post-v2.0 and hardened in v2.2 |
| `pact-siem` as separate crate with no kernel dependency | Kernel TCB isolation requirement | ✓ Verified |
| DPoP proof format is PACT-native (not HTTP-shaped) | Protocol neutrality | ✓ Shipped v2.0 |
| HA overrun bound is `max_cost_per_invocation x node_count` | Simple, documented, tested | ✓ Shipped v2.0 |
| Imported federated evidence stays outside native local receipt tables | Prevents contaminating local-only analytics and reputation semantics | ✓ Good |
| Federated lineage uses explicit bridge records instead of foreign parent FKs | Preserves local lineage integrity while enabling truthful multi-hop reconstruction | ✓ Good |
| Enterprise identity federation remains policy-visible instead of silently widening bearer trust | Admin and operator surfaces must explain cross-org identity admission decisions | ✓ Shipped v2.1 |
| Verifier policy distribution uses signed reusable artifacts plus persisted replay state | Verifier results must be portable and fail closed across processes and restarts | ✓ Shipped v2.1 |
| Multi-issuer passport semantics are a dedicated milestone, not an implicit verifier behavior | Prevents accidental trust widening | ✓ Shipped v2.1 |
| Shared remote evidence stays reference-based in analytics/reporting instead of being copied into native local history | Preserves truthful provenance and avoids contaminating local-only receipt semantics | ✓ Shipped v2.1 |
| v2.3 starts with hygiene and productionization instead of another feature wave | Feature breadth is ahead of release readiness and maintainability | ✓ Completed |
| Phase 21 should remove tracked generated artifacts before adding broader release docs | Reproducible release inputs are a prerequisite for credible qualification | ✓ Completed in Phase 21 |
| Phase 22 should prove the full release lane rather than relying on targeted local checks | Production readiness depends on one canonical scripted proof path | ✓ Completed in Phase 22 |
| Phase 23 should expose additive health/admin state instead of another opaque ready bit | Operators need actionable diagnostics without source spelunking | ✓ Completed in Phase 23 |
| Phase 24 should close with standards and launch evidence, not just roadmap completion | Production-candidate claims need auditable artifacts | ✓ Completed in Phase 24 |
| v2.4 should be an architecture milestone instead of shipping commercial trust primitives immediately | The next risk is maintainability and ownership radius, not missing breadth | Completed |
| The workspace should stay flat, and new crates should only be introduced at real service/storage/edge boundaries | Avoid churn for aesthetics while still extracting actual responsibilities | Completed |
| Crate extractions should preserve compatibility via facades and re-exports before deeper cleanups | Minimize breakage while large files are being decomposed | Completed |
| Commercial trust primitives move to v2.5 | New features should land on top of steadier boundaries, not giant mixed-concern crates | Planned |

---
*Last updated: 2026-03-25 after archiving v2.4*
