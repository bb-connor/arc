# PACT

## What This Is

PACT (Provable Agent Capability Transport) is a protocol and trust-control plane for secure, attested agent access to tools, resources, and cross-agent workflows. It combines capability-based security, cryptographic receipts, economic enforcement, portable trust credentials, and cross-org evidence exchange so operators can prove what an agent was allowed to do, what it actually did, and how that activity should be trusted across boundaries.

## Core Value

PACT must provide deterministic, least-privilege agent access with auditable outcomes, and produce cryptographic proof artifacts (receipts) that enable economic metering, regulatory compliance, and agent reputation.

## Current State

**Latest archived milestone:** v2.2 A2A and Ecosystem Hardening (archived 2026-03-25)
**Archive:** `.planning/milestones/v2.2-ROADMAP.md`
**Audit:** `.planning/milestones/v2.2-MILESTONE-AUDIT.md`
**Active milestone:** none
**Next planned milestone:** v2.3 Production and Standards

PACT has now closed and archived the v2.2 execution wave. Explicit A2A partner
hardening, durable lifecycle recovery, registry-backed certification
distribution, and the operator onboarding surfaces for those flows are all
implemented, verified, and snapshotted under `.planning/milestones/`.

## Latest Completed Milestone: v2.2 A2A and Ecosystem Hardening

**Goal:** Turn the shipped A2A adapter and certification skeleton into
partner-hardened, operator-usable product surfaces that can be adopted without
bespoke glue.

**Completed features:**
- Explicit A2A request shaping, fail-closed partner admission, and clearer
  auth diagnostics
- Durable long-running A2A task recovery with restart-safe follow-up
  correlation
- Certification registry publication, lookup, resolution, supersession, and
  revocation across CLI and trust-control
- Conformance, docs, and operator onboarding paths for the new A2A and
  certification lanes

## Next Milestone Candidate: v2.3 Production and Standards

**Current status:** planned, not yet defined in active requirements/phase
artifacts

**Expected focus areas:**
- protocol specification v2 alignment with the shipped portable-trust and
  federation surface
- deployment, runbook, and scale-hardening work for broader launch
- standards-submission artifacts for receipts and portable trust

## Requirements

### Validated

- ✓ Capability-scoped mediation, guard evaluation, and signed receipts -- v1.0
- ✓ MCP-compatible tool, resource, prompt, completion, logging, roots, sampling, and elicitation flows -- v1.0
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
- ✓ Receipt retention with time/size rotation and archived Merkle verification -- v2.0
- ✓ Colorado SB 24-205 compliance mapping document -- v2.0
- ✓ EU AI Act Article 19 compliance mapping document -- v2.0
- ✓ Receipt query API with 8-dimension filtering and cursor pagination -- v2.0
- ✓ TypeScript SDK 1.0 (@pact-protocol/sdk) with DPoP helpers -- v2.0
- ✓ SIEM exporters (Splunk HEC + Elasticsearch bulk) behind feature flag -- v2.0
- ✓ Capability lineage index with delegation chain tracking -- v2.0
- ✓ Receipt dashboard SPA with operator summaries, lineage, and portable comparison views -- v2.0
- ✓ Payment bridge substrate, truthful settlement model, and delegation-chain cost attribution -- post-v2.0
- ✓ Compliance evidence export and offline verification -- post-v2.0
- ✓ Python and Go SDKs moved to release-ready beta posture -- post-v2.0
- ✓ Local reputation scoring and reputation-gated issuance -- post-v2.0
- ✓ `did:pact`, Agent Passport alpha, challenge-bound presentation, and verifier evaluation -- post-v2.0
- ✓ A2A adapter alpha with streaming, task lifecycle, and broad auth-matrix support -- post-v2.0
- ✓ Identity federation alpha with OIDC/JWKS/introspection-backed stable subject derivation -- post-v2.0
- ✓ Bilateral evidence-sharing, federated evidence import, and multi-hop cross-org delegation -- post-v2.0
- ✓ Enterprise federation administration, provider-backed policy context, and operator-visible identity provenance -- v2.1
- ✓ Portable verifier policy artifacts and replay-safe verifier challenge handling -- v2.1
- ✓ Multi-issuer Agent Passport composition semantics and issuer-aware verification -- v2.1
- ✓ Shared remote evidence references and cross-org operator analytics/reporting -- v2.1
- ✓ Explicit A2A request shaping and fail-closed partner admission hardening -- v2.2
- ✓ Durable restart-safe A2A task correlation and follow-up validation -- v2.2
- ✓ Registry-backed certification publication, resolution, and revocation -- v2.2
- ✓ Operator-facing docs and regression coverage for the v2.2 A2A and certification surfaces -- v2.2

### Newly Completed

- [x] Remaining A2A auth matrix hardening, including provider-specific and
  non-header schemes
- [x] Durable long-running A2A lifecycle and follow-up recovery semantics
- [x] Federation-aware partner isolation and request-shaping for A2A peers
- [x] Certification registry/storage and certification status resolution
  surfaces
- [x] Conformance, operator docs, and onboarding surfaces for v2.2 partner
  adoption

### Out of Scope

- Full OS sandbox manager -- different product layer
- Multi-region Byzantine consensus -- premature at current scale
- Custom payment rail -- PACT is authorization, not settlement
- Protocol-level anti-collusion prevention -- still research, not an execution milestone
- Insurer and marketplace commercialization in v2.2 -- belongs in a later
  commercial milestone

## Context

PACT is a Rust workspace with protocol, kernel, CLI, portable-credential, reputation, A2A-adapter, SIEM, SDK, and conformance surfaces. v1.0 shipped the protocol foundation. v2.0 shipped the economic foundation. Subsequent execution extended that baseline with operator reporting, portable trust alpha, identity federation alpha, A2A alpha, and cross-org delegation/evidence-sharing primitives.

Key regulatory milestones achieved:
- Colorado SB 24-205 compliance document filed (deadline June 30, 2026)
- EU AI Act Article 19 compliance document filed (deadline August 2, 2026)

## Constraints

- **Tech stack**: Rust 2021 workspace, Rust 1.93 MSRV. pact-siem behind feature flag.
- **Compatibility**: v1.0 and v2.0 conformance must be preserved.
- **Security**: Fail-closed behavior maintained. DPoP enforcement wired into kernel evaluate pipeline.
- **Operational quality**: `cargo fmt`, `cargo clippy`, `cargo test --workspace` remain release gates.
- **Execution system**: `.planning/` is the active GSD source of truth for milestone and phase execution.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| PACT stays separate from ClawdStrike | Protocol must be vendor-neutral for standards submissions | ✓ Maintained |
| Single currency first for monetary budgets | Multi-currency adds exchange-rate complexity | ✓ Shipped v2.0 |
| Port ClawdStrike code rather than rewrite | Production-tested code adapted faster | ✓ DPoP, velocity, SIEM ported |
| Scope v2.0 to Q2-Q3 2026 | Hit regulatory deadlines | ✓ Shipped ahead of deadlines |
| Merkle commitment parallelized with monetary budgets | Both small enough for Q2 | ✓ Shipped together in Phase 8 |
| A2A adapter deferred to Q4 | A2A v1.0 spec stability uncertain | ✓ Shipped post-v2.0 and hardened in v2.2 |
| pact-siem as separate crate with no kernel dependency | Kernel TCB isolation requirement | ✓ Verified |
| DPoP proof format is PACT-native (not HTTP-shaped) | Protocol neutrality | ✓ Shipped v2.0 |
| HA overrun bound is max_cost_per_invocation x node_count | Simple, documented, tested | ✓ Shipped v2.0 |
| Imported federated evidence stays outside native local receipt tables | Prevents contaminating local-only analytics and reputation semantics | ✓ Good |
| Federated lineage uses explicit bridge records instead of foreign parent FKs | Preserves local lineage integrity while enabling truthful multi-hop reconstruction | ✓ Good |
| Enterprise identity federation remains policy-visible instead of silently widening bearer trust | Admin and operator surfaces must explain cross-org identity admission decisions | ✓ Shipped v2.1 |
| Verifier policy distribution uses signed reusable artifacts plus persisted replay state | Verifier results must be portable and fail closed across processes and restarts | ✓ Shipped v2.1 |
| Multi-issuer passport semantics are a dedicated milestone, not an implicit verifier behavior | Prevents accidental trust widening | ✓ Shipped v2.1 |
| Shared remote evidence stays reference-based in analytics/reporting instead of being copied into native local history | Preserves truthful provenance and avoids contaminating local-only receipt semantics | ✓ Shipped v2.1 |

---
*Last updated: 2026-03-25 after completing milestone v2.2 execution*
