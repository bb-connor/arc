# Requirements: PACT v2.0 Agent Economy Foundation

**Defined:** 2026-03-21
**Core Value:** PACT must provide deterministic, least-privilege agent access with auditable outcomes, and produce cryptographic proof artifacts that enable economic metering, regulatory compliance, and agent reputation.

## v1 Requirements

### Schema & Foundation

- [x] **SCHEMA-01**: pact-core types tolerate unknown fields (deny_unknown_fields removed from 18 types across capability.rs, receipt.rs, manifest.rs)
- [x] **SCHEMA-02**: ToolGrant supports monetary budget fields (max_cost_per_invocation, max_total_cost as MonetaryAmount with u64 minor-unit amounts)
- [x] **SCHEMA-03**: Attenuation enum supports cost reduction variants (ReduceCostPerInvocation, ReduceTotalCost)
- [x] **SCHEMA-04**: BudgetStore supports try_charge_cost for monetary budget enforcement with single-currency semantics
- [x] **SCHEMA-05**: Tool servers can report invocation cost via ToolInvocationCost struct
- [x] **SCHEMA-06**: Financial receipt metadata (FinancialReceiptMetadata) populated in receipt.metadata for monetary grants, including grant_index, cost_charged, budget_remaining, settlement_status

### Security

- [x] **SEC-01**: Receipt batches produce Merkle roots with signed kernel checkpoint statements
- [x] **SEC-02**: Receipt inclusion proofs verify against published checkpoint roots
- [x] **SEC-03**: DPoP per-invocation proofs bind to capability_id + tool_server + tool_name + action_hash + nonce (PACT-native proof message, not HTTP-shaped)
- [x] **SEC-04**: DPoP nonce replay store rejects reused nonces within configurable TTL window
- [x] **SEC-05**: Velocity guard denies requests exceeding configured invocation or spend windows per agent/grant using synchronous token bucket

### Compliance

- [x] **COMP-01**: Published document maps PACT receipts to Colorado SB 24-205 requirements for AI system output records
- [x] **COMP-02**: Published document maps PACT to EU AI Act Article 19 traceability requirements for high-risk AI systems
- [x] **COMP-03**: Receipt retention policies are configurable (time-based and size-based rotation)
- [x] **COMP-04**: Archived receipts remain verifiable via stored Merkle checkpoint roots
- [ ] **COMP-05**: At least 2 SIEM exporters functional and tested (ported from ClawdStrike: Splunk, Elastic, Datadog, Sumo Logic, Webhooks, or Alerting)

### Product Surface

- [ ] **PROD-01**: Receipt query API supports filtering by capability, tool, time range, outcome, and budget impact
- [ ] **PROD-02**: Capability lineage index persists capability snapshots keyed by capability_id with subject, issuer, grants, and delegation metadata
- [ ] **PROD-03**: Agent-centric receipt queries resolve through capability lineage index without replaying issuance logs
- [ ] **PROD-04**: Web-based receipt dashboard renders receipts filterable by agent/tool/outcome/time with delegation chain inspection
- [ ] **PROD-05**: Non-engineer stakeholders can answer "what did agent X do?" via dashboard without CLI access
- [x] **PROD-06**: TypeScript SDK published to npm at 1.0 with stable API contract and semantic versioning

## v2 Requirements

### Economic Integration (Q4 2026 - Q1 2027)

- **ECON-01**: Multi-currency monetary budgets with exchange-rate binding at grant issuance
- **ECON-02**: Payment rail bridge connecting PACT receipts to Stripe ACP or x402 settlement
- **ECON-03**: A2A trust adapter mediating agent-to-agent interactions with capability enforcement
- **ECON-04**: Cross-org delegation with federated capability delegation and bilateral receipt sharing
- **ECON-05**: Python SDK at 1.0 on PyPI, Go SDK at 1.0

### Reputation (Q1-Q2 2027)

- **REP-01**: Receipt-derived local reputation scores (reliability, compliance, scope discipline, budget adherence)
- **REP-02**: HushSpec reputation policy extensions for tier-gated capability issuance
- **REP-03**: Agent Passport v1 as W3C Verifiable Credential with did:pact DID method
- **REP-04**: PACT Certify v1 certification program for tool servers

## Out of Scope

| Feature | Reason |
|---------|--------|
| Custom payment rail | PACT is authorization/attestation, not settlement. Complement Stripe/x402/Coinbase. |
| Multi-region Byzantine consensus | HA leader/follower serves current scale. Byzantine tolerance premature. |
| Full OS sandbox manager | Root enforcement is the right abstraction. Sandboxing is a different product. |
| ML/LLM-based guards | Application-layer concern. Belongs in ClawdStrike, not protocol. |
| Fleet management | ClawdStrike's domain. PACT is the protocol, not the control plane. |
| Agent reputation (this milestone) | Requires capability lineage index and receipt analytics first. Q1 2027. |
| Multi-currency budgets (this milestone) | Single currency first. Multi-currency deferred to Q4 2026. |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SCHEMA-01 | Phase 7 | Complete |
| SCHEMA-02 | Phase 7 | Complete |
| SCHEMA-03 | Phase 7 | Complete |
| SCHEMA-04 | Phase 8 | Complete |
| SCHEMA-05 | Phase 8 | Complete |
| SCHEMA-06 | Phase 8 | Complete |
| SEC-01 | Phase 8 | Complete |
| SEC-02 | Phase 8 | Complete |
| SEC-03 | Phase 9 | Complete |
| SEC-04 | Phase 9 | Complete |
| SEC-05 | Phase 8 | Complete |
| COMP-01 | Phase 9 | Complete |
| COMP-02 | Phase 9 | Complete |
| COMP-03 | Phase 9 | Complete |
| COMP-04 | Phase 9 | Complete |
| COMP-05 | Phase 11 | Pending |
| PROD-01 | Phase 10 | Pending |
| PROD-02 | Phase 12 | Pending |
| PROD-03 | Phase 12 | Pending |
| PROD-04 | Phase 12 | Pending |
| PROD-05 | Phase 12 | Pending |
| PROD-06 | Phase 10 | Complete |

**Coverage:**
- v1 requirements: 22 total
- Mapped to phases: 22
- Unmapped: 0

---
*Requirements defined: 2026-03-21*
*Last updated: 2026-03-21 after milestone v2.0 roadmap creation*
