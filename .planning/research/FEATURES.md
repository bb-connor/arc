# Feature Research

**Domain:** Agent economic infrastructure -- authorization, metering, compliance, and attestation for autonomous agent systems
**Researched:** 2026-03-21
**Confidence:** HIGH (driven by first-party strategic documents, codebase analysis, and primary competitor research)

---

## Context: What Already Exists (v1.0)

This milestone is additive. The following are shipped and must not regress:

- Capability tokens with delegation chains, cascade revocation, and subject binding
- 7 composable fail-closed guards (forbidden-path, shell-command, egress-allowlist, path-allowlist, mcp-tool, secret-leak, patch-integrity)
- Signed receipts for every decision (allow/deny/cancelled/incomplete), stored in SQLite with HA replication
- Per-grant invocation budgets with HA replication
- MCP-compatible edge wrapping (tools, resources, prompts, completions, task lifecycle, nested flows)
- Remote HTTP hosting with JWT auth and OAuth server
- HA distributed trust-control cluster (leader/follower with sequence-based replication)

The v2.0 milestone adds: Merkle commitment, monetary budgets, receipt query/analytics, regulatory compliance story, SIEM export, and a receipt dashboard.

---

## Feature Landscape

### Table Stakes (Users Expect These)

Features that regulated enterprises and security-conscious operators assume exist before deploying PACT in production. Missing any of these means the product is not credible in target verticals (healthcare, financial services, legal).

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Monetary budget enforcement** | Every CFO understands "agent can spend up to $X." Invocation counts alone are not a business primitive -- dollars are. | HIGH | Extend `ToolGrant` with `MonetaryAmount`, `max_cost_per_invocation`, `max_total_cost`. Requires `deny_unknown_fields` migration first. See `AGENT_ECONOMY.md` section 3.1 for full design. |
| **Receipt query API** | Operators need to find specific receipts. Without filtering by capability, tool, time, and outcome, the receipt store is a write-only audit trail. | MEDIUM | SQLite queries + pagination. ClawdStrike `control-api/routes/receipts.rs` provides pagination and payload-limit patterns. Port and adapt. |
| **Receipt retention and rotation policy** | Any compliance officer asking about EU AI Act Article 19 will ask "how long are records kept and how do I configure that?" before deploying. | MEDIUM | Time-based and size-based rotation. Archived receipts must remain verifiable via Merkle proofs after rotation. |
| **Tamper-evident receipt log (Merkle commitment)** | The protocol spec and marketing documents describe "append-only Merkle-committed log." Without the wire connection, that claim is false. Regulators, auditors, and insurers (AIUC) require non-alterable records. | MEDIUM | `pact-core::merkle` already exists; wire into receipt pipeline with signed checkpoints. `CLAWDSTRIKE_INTEGRATION.md` section 3.5 documents the checkpoint schema port. |
| **Colorado AI Act compliance mapping** | Colorado SB 24-205 takes effect June 30, 2026 -- operators in affected verticals need to show compliance before that date. Missing this is a deployment blocker for US regulated customers. | LOW | Documentation artifact. Map PACT receipts to "records of AI system outputs and basis for those outputs." |
| **EU AI Act compliance mapping** | EU AI Act Article 19 takes effect August 2, 2026 for high-risk systems. Same deployment-blocker dynamic as Colorado. | LOW | Documentation artifact. Map receipt retention to "minimum period proportionate to intended purpose." |
| **Schema forward-compatibility (`deny_unknown_fields` removal)** | Adding any new fields to `ToolGrant` or receipt types without first removing `deny_unknown_fields` will cause old kernels to reject new tokens. This is a breaking change if not sequenced correctly. | MEDIUM | 18 instances across `capability.rs`, `receipt.rs`, `manifest.rs`. Must ship before any new fields appear on those types. |
| **TypeScript SDK at production quality** | Agent frameworks and enterprise integrations are primarily TS/JS. Developers cannot integrate without a stable SDK -- reading Rust source is not acceptable. | HIGH | Promote from alpha to 1.0. Stable API, error handling, retry semantics, npm published. |
| **Python SDK at beta quality** | Data science teams, AI framework integrations (LangGraph, CrewAI), and the majority of LLM tooling pipelines are Python. | HIGH | Promote from alpha to beta. Stable API, PyPI published, passes live conformance waves. |

### Differentiators (Competitive Advantage)

Features that no competitor (MCP, A2A, Stripe ACP, x402, UCAN) provides, or that PACT can provide significantly better. These are where PACT establishes its moat.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Velocity guard (spend and invocation windows)** | Enables CFO-grade controls: "agent may not spend more than $500/day" or "agent may not invoke more than 100 tool calls in any 1-hour window." No other agent protocol has this at the authorization layer. | MEDIUM | `MaxSpendPerWindow` and `MaxInvocationsPerWindow` constraint variants. Token-bucket implementation portable from ClawdStrike `async_guards/rate_limit.rs` (adapt to synchronous deny semantics). Per-agent and per-grant window accounting required. |
| **DPoP per-invocation proof-of-possession** | Subject binding already prevents cross-principal replay. DPoP adds freshness and nonce replay resistance -- each invocation requires a fresh signed proof. Closes the "stolen token is useless" story completely. No agent protocol has per-invocation proof-of-possession. | MEDIUM-HIGH | Port verification logic from ClawdStrike `clawdstrike-brokerd/src/capability.rs`. PACT-specific proof binding (not HTTP-shaped). Nonce replay store required. SDK helpers in both Rust and at least one SDK. |
| **Capability lineage index** | Without a deterministic join from `receipt.capability_id` to capability subject, agent-centric queries ("what did agent X do?") require replaying issuance logs. This is the substrate for analytics, billing, and reputation. No competitor has this. | HIGH | Native PACT work -- no ClawdStrike equivalent. Persist capability snapshots keyed by `capability_id` with subject, issuer, grants, and delegation metadata. Prerequisite for receipt dashboard and analytics. |
| **Receipt dashboard (compliance officer UX)** | A non-engineer compliance officer must be able to answer "what did agent X do last Tuesday?" without CLI access. This is the product surface that converts regulatory pressure into deployment decisions. No agent protocol has this. | HIGH | Web-based receipt viewer. Filter by agent/tool/outcome/time. Inspect delegation chains. View budget consumption. Read-only. Depends on receipt query API and capability lineage index. |
| **SIEM integration (6 exporters)** | Enterprise security teams expect receipts in Splunk, Elastic, Datadog, Sumo Logic, or their SIEM of choice. Without SIEM integration, PACT receipts are invisible to existing security tooling stacks. Only PACT has cryptographically signed action receipts to export. | MEDIUM | Port `pact-siem` from ClawdStrike 6 exporters. ECS, CEF, OCSF, Native schema formats. ExporterManager for fan-out. Dead letter queue. Per-exporter rate limiting. Feature-flag the crate. |
| **Financial receipt metadata (FinancialReceiptMetadata)** | The receipt log becomes a billing ledger when monetary context is embedded: cost charged, currency, budget remaining, settlement status, delegation depth, root budget holder. No competitor produces receipts with this structure. | MEDIUM | Structured `FinancialReceiptMetadata` injected into `PactReceipt.metadata` under the `"financial"` key. Kernel populates post-charge. Receipt store adds `cost_charged` and `cost_currency` indexed columns for billing queries. |
| **Spending delegation attenuation (ReduceCostPerInvocation, ReduceTotalCost)** | Delegation chains that carry monetary budget narrowing: an agent can delegate a capability and guarantee the child cannot spend more than a suballocated amount. No payment protocol has this at the authorization layer -- Stripe ACP and AP2 cannot express "child agent gets at most $50 of my $500 budget." | MEDIUM | New `Attenuation` variants. `ToolGrant::is_subset_of` enforcement for cost fields. Pre-reservation of child budget against parent. |
| **Merkle inclusion proofs for compliance auditors** | An auditor can verify that a specific receipt was included in the Merkle tree at checkpoint time, using only the Merkle root (published by the kernel) and the inclusion proof. This is forensic-quality evidence, not log-file evidence. | MEDIUM | Checkpoint schema, signed checkpoint storage, inclusion proof query. Builds on Merkle commitment (table stakes). |

### Anti-Features (Commonly Requested, Often Problematic)

Features that surface as user requests or appear on competitor roadmaps but create more problems than they solve for PACT specifically.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| **Custom payment rail / settlement engine** | "PACT has receipts, add a settlement button" -- natural request from design partners wanting end-to-end automation. | PACT is the authorization and attestation layer. Building a payment rail means competing with Stripe, Coinbase, and Visa while adding regulatory burden (money transmission licenses, PCI DSS, fraud liability). The protocol's vendor-neutrality depends on it not moving money. | `PaymentAdapter` trait for plugging in any rail (Stripe, x402, stablecoin). PACT authorizes; the rail settles. See `AGENT_ECONOMY.md` section 3.6 for the correct abstraction. |
| **Multi-currency budgets with exchange-rate binding** | Enterprise global deployments operate in multiple currencies. "Why can't I budget in EUR and pay in USD?" | Exchange-rate binding adds significant complexity: rate source selection, rate freshness, dispute resolution when rates move mid-invocation. This is a Q4 2026 concern after single-currency proves out. Adding it now delays the Colorado deadline. | Single currency first. Design the `MonetaryAmount` type with `currency: String` to support multi-currency later without schema changes. |
| **ML-based guards (jailbreak, prompt injection)** | Customers ask for AI safety guardrails alongside protocol-level controls. | ML-based guards require model inference, vendor-specific scoring, and deployment complexity that does not belong in a vendor-neutral protocol. They belong in ClawdStrike (the product), not PACT (the protocol). Protocol purity is required for standards submissions. | The 7 fail-closed protocol guards are PACT's guard surface. Document ClawdStrike as the path for ML-based detection. |
| **Agent reputation scoring (scoring engine)** | "You have all the receipt data, just compute a score." Frequently requested by insurance-adjacent design partners. | Reputation scoring depends on the capability lineage index (Q3 prerequisite) and a well-defined scoring model (Q1 2027). Shipping an ungrounded scoring engine before the data substrate is correct produces non-reproducible scores and poisons the reputation story. | Ship the capability lineage index and per-grant join path first. Let the data accumulate. Design the scoring model in Q1 2027 once the substrate is correct. |
| **Fleet management / control plane console** | Enterprises ask for tenant management, agent enrollment, policy CRUD, and billing in a single UI. | Fleet management is an application-layer concern specific to ClawdStrike's deployment model. Including it in PACT undermines vendor neutrality and creates competing priorities with the protocol work. | ClawdStrike provides the fleet management surface. PACT provides the protocol primitives that ClawdStrike builds on. |
| **Multi-region Byzantine consensus** | Security-conscious enterprise architects ask about geographic redundancy and adversarial node scenarios. | Byzantine tolerance is architecturally premature at current scale and would turn the milestone into a separate distributed-systems program. The HA leader/follower model handles current operational requirements. | Document the HA model's guarantees honestly. Position Byzantine consensus as Q3 2027+ when cross-org receipts require it. |
| **Real-time streaming analytics / OLAP layer** | Dashboards that show live spend rates, per-second invocation counts, and trending anomalies. | Real-time streaming adds architectural complexity (Kafka/NATS, windowing, state management) that is disproportionate to the Q2/Q3 scope. The receipt dashboard is read-only batch queries over the SQLite store. | Polling-based dashboard over the indexed SQLite receipt store is sufficient for initial compliance use cases. Streaming anomaly detection is Q1 2027 (PACT Watch). |
| **A2A trust adapter (now)** | "A2A has 150+ partners, integrate today." Obvious ecosystem expansion play. | A2A spec stability is uncertain. Google may make breaking changes before v1.0 stabilizes. Designing a tight adapter now risks rework. A thin adapter that changes with the spec is lower-risk. | Defer A2A adapter to Q4 2026. Monitor spec stability. Design as thin adapter with bounded rework surface. |

---

## Feature Dependencies

```
deny_unknown_fields removal (schema migration)
    └──required by──> MonetaryAmount + ToolGrant cost fields
                           └──required by──> try_charge_cost (BudgetStore)
                           └──required by──> FinancialReceiptMetadata
                           └──required by──> Spending delegation attenuation

Merkle commitment (receipt pipeline wiring)
    └──required by──> Merkle inclusion proofs
    └──required by──> Receipt retention and rotation (archived receipts verifiable)
    └──required by──> Colorado / EU compliance story (tamper-evident claim must be real)

Receipt query API
    └──required by──> Receipt dashboard
    └──required by──> SIEM exporters (query receipts for export batches)

Capability lineage index
    └──required by──> Receipt dashboard (agent-centric joins)
    └──required by──> Receipt analytics API (per-agent aggregation)
    └──required by──> Agent reputation scoring (Q1 2027, out of scope for v2.0)

FinancialReceiptMetadata
    └──required by──> Receipt dashboard (budget consumption view)
    └──required by──> SIEM exporters (financial context in events)
    └──required by──> Payment rail bridge (Q4 2026, out of scope for v2.0)

TypeScript SDK 1.0
    └──required by──> Design partner adoption
    └──required by──> DPoP SDK helpers (DPoP is incomplete without SDK proof generation)

Velocity guard
    └──enhances──> Monetary budgets (time-window spending caps complement total caps)
    └──depends on──> ToolGrant cost fields (for MonetarySpendPerWindow variant)
```

### Dependency Notes

- **`deny_unknown_fields` removal requires no prior feature but blocks everything else:** All new fields on `ToolGrant`, `CapabilityToken`, and receipt types will break old kernels unless the schema migration ships first. This must be the first item in the Q2 work sequence.
- **Merkle commitment is a prerequisite for compliance claims:** Colorado and EU compliance documents reference "tamper-evident" receipt logs. That claim cannot be made until Merkle commitment is wired into the pipeline, not just coded in `pact-core::merkle`. The code exists; the gap is wiring.
- **Capability lineage index gates the receipt dashboard:** Agent-centric queries ("what did agent X do?") require joining receipts to capability subjects. Without the lineage index, the dashboard can only show receipts by tool or time, not by agent identity. This means the Q3 dashboard depends on the Q3 lineage index -- both must ship together.
- **DPoP conflicts with being marked "complete" without SDK helpers:** Porting only the kernel verifier is not enough. Agents need SDK-side proof generation. Mark DPoP incomplete until Rust + at least one SDK has working proof generation with replay rejection. The ClawdStrike source provides the verifier side only.
- **SIEM exporters enhance but do not require financial metadata:** SIEM export works on plain receipts. The financial metadata enriches the SIEM events but is not a blocker for the basic export path.

---

## MVP Definition

This milestone is v2.0 of an existing protocol (v1.0 is shipped). The "MVP" here means the minimum that hits the regulatory deadlines and establishes the economic primitive credibly.

### Launch With (v2.0, Q2-Q3 2026)

- [ ] **`deny_unknown_fields` removal** -- everything else is blocked until this ships
- [ ] **Merkle receipt commitment with signed checkpoints** -- tamper-evident claims must be backed by code before Colorado deadline
- [ ] **Monetary budgets (single currency)** -- the single most important product primitive; makes PACT legible to CFOs and compliance teams
- [ ] **Colorado AI Act compliance mapping** -- hard deadline June 30, 2026
- [ ] **EU AI Act compliance mapping** -- hard deadline August 2, 2026
- [ ] **Receipt query API** -- write-only audit trail is not useful; filtering is the minimum for any compliance use
- [ ] **Receipt retention and rotation** -- EU Article 19 requires configurable retention; without it the compliance story is incomplete
- [ ] **Velocity guard** -- time-window controls are the complement to total budget caps; together they provide CFO-grade spending governance
- [ ] **Capability lineage index** -- prerequisite for the dashboard and for honest agent-centric analytics
- [ ] **Receipt dashboard** -- the product surface that makes receipts legible to non-engineers; compliance officers need this before production deployments
- [ ] **TypeScript SDK 1.0** -- adoption blocker for the largest developer population
- [ ] **SIEM exporters (at least 2)** -- enterprise security teams require SIEM visibility; receipt data is invisible without it

### Add After Validation (v2.x, Q3-Q4 2026)

- [ ] **DPoP per-invocation proofs** -- adds freshness/replay resistance to subject binding; important for high-security deployments but not a blocker for initial adoption; defer if Q2 scope pressure mounts
- [ ] **Python SDK 1.0** -- promote from beta after TS SDK proves the SDK model; triggers when design partners demonstrate Python integration
- [ ] **Go SDK 1.0** -- deferred to Q4 per strategic roadmap
- [ ] **FinancialReceiptMetadata enrichment in SIEM events** -- adds billing context to exports; triggers when monetary budgets are in production use
- [ ] **Receipt analytics API (aggregations)** -- once the lineage index is live, add reliability/compliance/budget-utilization aggregations; triggers when design partners need aggregate views
- [ ] **Payment rail bridge (Stripe or x402)** -- Q4 2026; triggers after monetary budgets prove stable in production
- [ ] **ClawdStrike dependency restructure** -- Q3 2026; triggers when pact-core API is stable enough to pin
- [ ] **Tool manifest pricing metadata** -- lets tool servers advertise cost before invocation; triggers when monetary budgets create demand for pre-execution price discovery

### Future Consideration (v3+, Q1 2027 and beyond)

- [ ] **Agent reputation scoring** -- depends on capability lineage index + sufficient receipt volume; Q1 2027
- [ ] **Agent Passports (W3C Verifiable Credentials)** -- depends on `did:pact` DID method; Q1-Q2 2027
- [ ] **Cross-org delegation and settlement** -- depends on payment rail bridge stability; Q2 2027
- [ ] **Multi-currency budgets with exchange-rate binding** -- defer until single-currency proves out; Q4 2026 at earliest
- [ ] **Receipt-linked settlement (production-grade)** -- Q2 2027 after payment rail bridge proves the model
- [ ] **Parametric insurance integration** -- Q2 2027 after reputation and settlement infrastructure exists

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| `deny_unknown_fields` removal | HIGH (unblocks everything) | MEDIUM | P1 |
| Merkle receipt commitment | HIGH (compliance credibility) | MEDIUM | P1 |
| Monetary budgets (single currency) | HIGH (CFO/compliance primitive) | HIGH | P1 |
| Colorado compliance mapping | HIGH (June 2026 deadline) | LOW | P1 |
| EU AI Act compliance mapping | HIGH (August 2026 deadline) | LOW | P1 |
| Receipt query API | HIGH (usability) | MEDIUM | P1 |
| Capability lineage index | HIGH (gates dashboard + analytics) | HIGH | P1 |
| Receipt dashboard | HIGH (compliance officer UX) | HIGH | P1 |
| TypeScript SDK 1.0 | HIGH (adoption) | HIGH | P1 |
| Receipt retention and rotation | HIGH (Article 19 compliance) | MEDIUM | P1 |
| Velocity guard | HIGH (spending governance) | MEDIUM | P1 |
| SIEM exporters (2+) | HIGH (enterprise security stack) | MEDIUM | P2 |
| DPoP per-invocation proofs | MEDIUM (adds freshness to existing binding) | MEDIUM-HIGH | P2 |
| FinancialReceiptMetadata | MEDIUM (enriches receipts) | MEDIUM | P2 |
| Python SDK 1.0 | MEDIUM (second-largest developer population) | HIGH | P2 |
| ClawdStrike dependency restructure | MEDIUM (internal architecture) | MEDIUM | P2 |
| Tool manifest pricing metadata | MEDIUM (pre-execution price discovery) | LOW | P2 |
| Receipt analytics API | MEDIUM (aggregate views) | MEDIUM | P2 |
| Payment rail bridge | HIGH (economic integration) | HIGH | P3 |
| Multi-currency budgets | MEDIUM (global enterprise) | HIGH | P3 |
| Agent reputation scoring | HIGH (long-term moat) | HIGH | P3 |

**Priority key:**
- P1: Required for v2.0 launch (Q2-Q3 2026, regulatory deadlines)
- P2: Ship in v2.x if capacity allows; become P1 in next cycle if deferred
- P3: Future milestone (Q4 2026 or later); do not start until P1 and P2 are complete

---

## Competitor Feature Analysis

| Feature | Stripe ACP / x402 | A2A / MCP | UCAN | PACT v2.0 |
|---------|-------------------|-----------|------|-----------|
| Monetary spending caps | Yes (payment domain only) | No | No | Yes (tool-invocation authorization layer) |
| Velocity / rate controls | Stripe: yes (card limits) | No | No | Yes (VelocityGuard with per-agent/per-grant windows) |
| Signed action receipts | Payment receipt only | No | Optional (UCAN invocation spec) | Every decision, signed, Merkle-committed |
| Compliance-ready retention | No | No | No | Yes (configurable retention + rotation + Merkle proof) |
| Receipt dashboard | No | No | No | Yes (Q3 2026) |
| SIEM integration | Webhook (Stripe Sigma) | No | No | 6 exporters (Splunk, Elastic, Datadog, Sumo Logic, Webhooks, Alerting) |
| Delegation chain budget attenuation | No | No | No (budget constraints not in UCAN token) | Yes (ReduceCostPerInvocation, ReduceTotalCost) |
| Tamper-evident log (Merkle) | On-chain for x402 | No | No | Yes (signed checkpoints, inclusion proofs) |
| Colorado / EU AI Act mapping | No | No | No | Yes (documentation artifacts, published pre-deadline) |
| Per-invocation proof-of-possession | x402: payment proof only | No | DID-bound (not per-invocation fresh) | Yes (DPoP, Q2-Q3 2026) |
| Standards-submittable protocol | No | MCP: partial | Yes (UCAN spec) | Yes (goal: IETF/W3C submission) |
| Formal safety proofs | No | No | No | Yes (P1-P5, Lean 4) |

PACT's v2.0 feature set is differentiated across all compliance-relevant dimensions. The closest competitor is UCAN on the capability token structure, but UCAN has no monetary budgets, no mandatory receipts, no Merkle commitment (receipts optional in UCAN spec), no compliance documentation, and no SIEM integration.

---

## Sources

- `docs/AGENT_ECONOMY.md` -- technical design for monetary budgets, velocity controls, receipt metadata, payment rail abstraction
- `docs/CLAWDSTRIKE_INTEGRATION.md` -- code port plan (DPoP, receipt query, velocity guard, SIEM exporters, Merkle checkpoint)
- `docs/STRATEGIC_ROADMAP.md` -- quarterly sequencing and decision gates Q2 2026 through Q4 2027
- `docs/VISION.md` -- competitive positioning and the agent economy thesis
- `docs/COMPETITIVE_LANDSCAPE.md` -- primary analysis of A2A, MCP, ANP, Stripe ACP, x402, AP2, UCAN, AIUC, SPIFFE
- `docs/research/AGENT_ECONOMY_RESEARCH.md` -- market data, regulatory research, attestation precedents (marine/automotive/finance)
- `.planning/PROJECT.md` -- v2.0 milestone scope, active requirements, regulatory deadlines, constraints

---

*Feature research for: PACT v2.0 Agent Economy Foundation*
*Researched: 2026-03-21*
