# Milestones

## v2.4 Architecture and Runtime Decomposition (Completed: 2026-03-25)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Extracted `pact-control-plane` and `pact-hosted-mcp` so `pact-cli` no longer
  owns long-lived service implementations directly.
- Moved SQLite-backed store, query, report, and export implementations into
  `pact-store-sqlite`, leaving `pact-kernel` closer to an enforcement-core
  facade.
- Split MCP runtime transport into `pact-mcp-edge` and decomposed
  `pact-a2a-adapter` into concern-based modules with compatibility preserved.
- Reduced `pact-credentials`, `pact-reputation`, and `pact-policy` entry files
  to thin facades and added a fail-closed workspace layering guard.

---

## v2.3 Production and Standards (Completed: 2026-03-25)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Shipped source-only release inputs, packaging guards, and a cleaner CLI admin
  ownership boundary.
- Shipped one canonical release-qualification lane covering workspace,
  dashboard, SDK packages, live conformance, and repeat-run trust-cluster
  behavior.
- Shipped supported observability and health contracts for trust-control,
  hosted edges, federation, and A2A diagnostics.
- Shipped protocol v2 alignment, standards-submission draft artifacts, and
  launch-readiness evidence for the production candidate.

---

## v2.2 A2A and Ecosystem Hardening (Completed: 2026-03-25)

**Phases completed:** 4 phases, 12 plans

**Key accomplishments:**
- Shipped explicit A2A request shaping plus fail-closed partner admission and
  clearer operator-visible auth diagnostics.
- Shipped durable A2A task-registry persistence and restart-safe follow-up
  validation tied to the originating partner and interface binding.
- Shipped registry-backed certification publication, lookup, resolution,
  supersession, and revocation across CLI and trust-control.
- Shipped operator docs, regression coverage, and planning traceability for the
  completed v2.2 surfaces.

---

## v2.1 Federation and Verifier Completion (Shipped: 2026-03-24)

**Phases completed:** 4 phases, 15 plans

**Key accomplishments:**
- Shipped enterprise federation administration with provider-backed identity normalization, SCIM/SAML surfaces, and policy-visible provenance.
- Shipped signed reusable verifier-policy artifacts plus replay-safe persisted challenge state across CLI and remote verifier flows.
- Shipped truthful multi-issuer passport composition with issuer-aware evaluation, reporting, and regression coverage.
- Shipped shared-evidence federation analytics across operator reports, reputation comparison, CLI, and dashboard surfaces.

---

## v2.0 Agent Economy Foundation (Shipped: 2026-03-24)

**Phases completed:** 6 phases, 19 plans

**Key accomplishments:**
- Shipped monetary budgets, truthful settlement metadata, Merkle checkpoints, retention/archival, and receipt analytics.
- Shipped receipt query APIs, operator reporting, compliance evidence export and verification, and the receipt dashboard.
- Shipped local reputation scoring, reputation-gated issuance, `did:pact`, Agent Passport alpha, verifier evaluation, and challenge-bound presentation flows.
- Shipped A2A adapter alpha with streaming, task lifecycle, auth-matrix coverage, and identity federation alpha.
- Shipped bilateral evidence-sharing, federated evidence import, portable comparison surfaces, and multi-hop cross-org delegation.

---

## v1.0 Closing Cycle (Complete)

**Completed:** 2026-03-20
**Phases:** 6 (all complete, 24 plans executed)
**Summary:** Shipped the protocol foundation: capability-scoped mediation, fail-closed guards, signed receipts, MCP-compatible edge with tools/resources/prompts/completions/nested flows/auth/notifications/task lifecycle, HA distributed trust-control with deterministic leader election, cross-language conformance (JS/Python), and release qualification.

**Validated requirements:**
- Capability-scoped mediation, guard evaluation, and signed receipts
- MCP-compatible tool, resource, prompt, completion, logging, roots, sampling, and elicitation flows
- Live conformance waves against JS and Python peers
- HA trust-control determinism and reliability
- Roots enforced as filesystem boundary
- Remote runtime lifecycle hardening
- Cross-transport task/stream/cancellation semantics
- Unified policy surface (HushSpec canonical, PACT YAML compat)
- Release qualification with conformance + repeat-run trust-cluster proof
