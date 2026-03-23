# PACT

## What This Is

PACT (Provable Agent Capability Transport) is a protocol for secure, attested tool access in AI agent systems. It replaces MCP with a ground-up design built on capability-based security, cryptographic attestation, and privilege separation. v2.0 ships the economic foundation: monetary budget enforcement, Merkle-committed receipt batches, DPoP proof-of-possession, regulatory compliance tooling, SIEM integration, and a web-based receipt dashboard with capability lineage tracking.

## Core Value

PACT must provide deterministic, least-privilege agent access with auditable outcomes, and produce cryptographic proof artifacts (receipts) that enable economic metering, regulatory compliance, and agent reputation.

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
- ✓ Receipt dashboard SPA (React 18 / Vite 6 / TanStack Table 8 / Recharts 2) -- v2.0

### Active

- [ ] Multi-currency monetary budgets with exchange-rate binding
- [ ] Payment rail bridge (Stripe ACP / x402 settlement)
- [ ] A2A trust adapter for agent-to-agent interactions
- [ ] Cross-org delegation with federated capability delegation
- [ ] Python SDK 1.0, Go SDK 1.0
- [ ] Agent reputation scoring (receipt-derived local scores)

### Out of Scope

- Agent Passports / W3C VCs -- deferred to Q2 2027
- Full OS sandbox manager -- different product layer
- Multi-region Byzantine consensus -- premature at current scale
- Custom payment rail -- PACT is authorization, not settlement
- ML/LLM-based guards -- application-layer concern (ClawdStrike domain)

## Context

PACT is a Rust workspace with 10 crates (pact-core, pact-kernel, pact-manifest, pact-mcp-adapter, pact-guards, pact-policy, pact-bindings-core, pact-conformance, pact-siem, pact-cli), a TypeScript SDK (@pact-protocol/sdk 1.0.0), Lean 4 formal proofs, and 300+ tests. v1.0 shipped the protocol foundation (6 phases). v2.0 shipped the economic foundation (6 phases, 19 plans).

Key regulatory milestones achieved:
- Colorado SB 24-205 compliance document filed (deadline June 30, 2026)
- EU AI Act Article 19 compliance document filed (deadline August 2, 2026)

## Constraints

- **Tech stack**: Rust 2021 workspace, Rust 1.93 MSRV. pact-siem behind feature flag.
- **Compatibility**: v1.0 and v2.0 conformance must be preserved.
- **Security**: Fail-closed behavior maintained. DPoP enforcement wired into kernel evaluate pipeline.
- **Operational quality**: `cargo fmt`, `cargo clippy`, `cargo test --workspace` remain release gates.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| PACT stays separate from ClawdStrike | Protocol must be vendor-neutral for standards submissions | ✓ Maintained |
| Single currency first for monetary budgets | Multi-currency adds exchange-rate complexity | ✓ Shipped v2.0 |
| Port ClawdStrike code rather than rewrite | Production-tested code adapted faster | ✓ DPoP, velocity, SIEM ported |
| Scope v2.0 to Q2-Q3 2026 | Hit regulatory deadlines | ✓ Shipped ahead of deadlines |
| Merkle commitment parallelized with monetary budgets | Both small enough for Q2 | ✓ Shipped together in Phase 8 |
| A2A adapter deferred to Q4 | A2A v1.0 spec stability uncertain | -- Pending |
| pact-siem as separate crate with no kernel dependency | Kernel TCB isolation requirement | ✓ Verified |
| DPoP proof format is PACT-native (not HTTP-shaped) | Protocol neutrality | ✓ Shipped v2.0 |
| HA overrun bound is max_cost_per_invocation x node_count | Simple, documented, tested | ✓ Shipped v2.0 |

---
*Last updated: 2026-03-23 after v2.0 milestone completion*
