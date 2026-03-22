# PACT

## What This Is

PACT (Provable Agent Capability Transport) is a protocol for secure, attested tool access in AI agent systems. It replaces MCP with a ground-up design built on capability-based security, cryptographic attestation, and privilege separation. The v1.0 protocol foundation is complete. The project is now evolving into the economic substrate for the agent economy -- the authorization, attestation, and metering layer that sits above any payment rail.

## Core Value

PACT must provide deterministic, least-privilege agent access with auditable outcomes, and produce cryptographic proof artifacts (receipts) that enable economic metering, regulatory compliance, and agent reputation.

## Current Milestone: v2.0 Agent Economy Foundation

**Goal:** Transform PACT from a security protocol into economic infrastructure for autonomous agent systems. Ship Merkle-committed receipts, monetary budgets, compliance-ready tooling, and the data substrate for agent reputation. Hit Colorado (June 2026) and EU AI Act (Aug 2026) regulatory deadlines.

**Target features:**
- Merkle receipt commitment (wire existing module into pipeline with signed checkpoints)
- Monetary budgets (single currency, extend ToolGrant with cost fields)
- pact-core schema migration (remove deny_unknown_fields, add forward compatibility)
- Colorado AI Act + EU AI Act compliance mapping documents
- DPoP proof-of-possession (port from ClawdStrike)
- Receipt query API (port from ClawdStrike)
- Velocity guard (port from ClawdStrike)
- Capability lineage index (native PACT work for agent-centric joins)
- Receipt dashboard (web-based receipt viewer)
- SDK hardening (TypeScript to 1.0, Python to beta)
- SIEM exporters (port 6 from ClawdStrike)
- ClawdStrike dependency restructure (pact-core as canonical source)

## Requirements

### Validated

- ✓ Capability-scoped mediation, guard evaluation, and signed receipts — v1.0
- ✓ MCP-compatible tool, resource, prompt, completion, logging, roots, sampling, and elicitation flows — v1.0
- ✓ Live conformance waves against JS and Python peers — v1.0
- ✓ HA trust-control determinism and reliability — v1.0
- ✓ Roots enforced as filesystem boundary — v1.0
- ✓ Remote runtime lifecycle hardening — v1.0
- ✓ Cross-transport task/stream/cancellation semantics — v1.0
- ✓ Unified policy surface (HushSpec canonical, PACT YAML compat) — v1.0
- ✓ Release qualification with conformance + repeat-run proof — v1.0

### Active

- [ ] Merkle receipt commitment with signed checkpoints
- [ ] Monetary budgets (single currency)
- [ ] pact-core schema migration (deny_unknown_fields removal)
- [ ] Colorado AI Act compliance mapping
- [ ] EU AI Act compliance mapping
- [ ] DPoP proof-of-possession
- [ ] Receipt query API
- [ ] Velocity guard
- [ ] Capability lineage index
- [ ] Receipt dashboard
- [ ] TypeScript SDK 1.0
- [ ] Python SDK beta
- [ ] SIEM exporters (at least 2)
- [ ] ClawdStrike dependency restructure
- [ ] Receipt retention and rotation

### Out of Scope

- Multi-currency budgets with exchange-rate binding — deferred to Q4 2026, single currency first
- A2A trust adapter — contingent on A2A v1.0 spec stability, deferred to Q4 2026
- Payment rail bridge — deferred to Q4 2026 after monetary budgets prove out
- Agent reputation scoring — deferred to Q1 2027 after capability lineage index ships
- Agent Passports / W3C VCs — deferred to Q2 2027
- Full OS sandbox manager — different product layer
- Multi-region Byzantine consensus — premature at current scale
- Custom payment rail — PACT is authorization, not settlement

## Context

PACT is a brownfield Rust workspace with 9 crates, 3 language SDKs (TS, Python, Go), Lean 4 formal proofs, and 270+ tests. The v1.0 closing cycle completed all 6 phases with green local release qualification.

The v2.0 milestone is driven by three strategic documents:
- `docs/VISION.md` — positioning PACT as the economic substrate for the agent economy
- `docs/STRATEGIC_ROADMAP.md` — quarterly roadmap Q2 2026 through Q4 2027
- `docs/CLAWDSTRIKE_INTEGRATION.md` — code port plan from ClawdStrike (DPoP, receipt API, velocity, SIEM, checkpoints)

Key external forcing functions:
- Colorado AI Act takes effect June 30, 2026
- EU AI Act high-risk provisions take effect August 2, 2026
- NIST AI Agent Standards Initiative RFI deadline April 2, 2026

ClawdStrike (sibling project at ../clawdstrike) has production implementations of DPoP, receipt query API, velocity guards, and 6 SIEM exporters that can be ported to accelerate this milestone.

## Constraints

- **Tech stack**: Rust 2021 workspace, Rust 1.93 MSRV. New modules should fit existing crate boundaries before adding crates.
- **Compatibility**: v1.0 conformance wins must be preserved. JS/Python live waves must not regress.
- **Security**: Fail-closed behavior must be maintained. deny_unknown_fields removal must be sequenced carefully.
- **Regulatory**: Colorado (June 2026) and EU (August 2026) compliance stories must ship before those dates.
- **ClawdStrike ports**: Ported code must be adapted to PACT types (not copy-paste). pact-core is the canonical source.
- **Operational quality**: `cargo fmt`, `cargo clippy`, `cargo test --workspace` remain release gates.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| PACT stays separate from ClawdStrike | Protocol must be vendor-neutral for standards submissions and ecosystem adoption. ClawdStrike becomes "powered by PACT" | — Pending |
| Single currency first for monetary budgets | Multi-currency adds exchange-rate complexity. Ship the primitive, iterate. | — Pending |
| Port ClawdStrike code rather than rewrite | DPoP, receipt API, velocity, SIEM already production-tested. Adaptation is faster than greenfield. | — Pending |
| Scope v2.0 to Q2-Q3 2026 | Two quarters is enough to ship the economic foundation and hit regulatory deadlines. Reputation and settlement are Q1-Q2 2027. | — Pending |
| Merkle commitment parallelized with monetary budgets | Small enough to ship together in Q2. Security claims must be backed by shipping code. | — Pending |
| A2A adapter deferred to Q4 | A2A v1.0 spec stability uncertain. Design as thin adapter so rework is bounded. | — Pending |

---
*Last updated: 2026-03-21 after v2.0 milestone initialization*
