# PACT Strategic Roadmap: Q2 2026 -- Q4 2027

**Date:** 2026-03-21
**Status:** Approved after internal debate
**Scope:** Post-v1 RC strategic direction through initial market traction

---

## Debate Summary

Three perspectives argued over PACT's post-v1 direction. Their positions, disagreements, and resolution are recorded here so readers understand why the roadmap is sequenced the way it is.

### Perspective A: The Protocol Purist

PACT's value proposition is trust. If the trust claims are hollow, nothing else matters. The Merkle tree commitment code exists in `pact-core/src/merkle.rs` but is not wired into the receipt pipeline. That means the "append-only Merkle-committed log" described in the protocol spec and the vision document is marketing, not engineering. DPoP is specified as a sender constraint on capability tokens but not implemented as per-invocation proof-of-possession. The Lean 4 proofs have a known `sorry` for BEq transitivity.

These are not minor gaps. They are the difference between "PACT signs receipts" and "PACT produces non-repudiable evidence." Every competitor will eventually sign things. The moat is in the rigor: Merkle commitment makes the receipt log tamper-evident, DPoP prevents token replay, and complete formal proofs make the security claims machine-checkable rather than marketing-checkable. Ship these before adding economic features, because adding economic features on top of incomplete security foundations invites the worst kind of failure -- the kind where money is lost and the audit trail turns out to be forgeable.

The formal proofs also serve a regulatory purpose. The EU AI Act and Colorado AI Act both require demonstrable traceability. "We have Lean 4 proofs that our receipt chain has integrity" is a defensible statement in a regulatory filing. "We have a Merkle module that is not connected to anything" is not.

### Perspective B: The Product Builder

Nobody has ever bought a protocol because of its Lean 4 proofs. The regulatory deadlines are real -- Colorado AI Act takes effect June 30, 2026, EU AI Act high-risk provisions take effect August 2026 -- but what matters is having something enterprises can deploy before those dates, not having a mathematically complete receipt chain that nobody is using.

The immediate gap is product surface. PACT has invocation-count budgets but not monetary budgets. It has signed receipts but no way to query, aggregate, or visualize them. It has TS, Python, and Go SDKs at alpha quality but no production-grade client libraries. The MCP adapter wraps existing servers, the first A2A adapter now covers discovery plus blocking `SendMessage`, `SendStreamingMessage`, follow-up `GetTask`, follow-up `SubscribeToTask`, follow-up `CancelTask`, push-notification config CRUD, fail-closed bearer and API-key header/query/cookie auth negotiation from Agent Card metadata, fail-closed `stateTransitionHistory` enforcement for `historyLength` usage, fail-closed task/status lifecycle payload validation, OAuth2 client-credentials and OpenID Connect token acquisition, truthful mTLS transport with custom root CA support, and tenant-aware HTTP path shaping, but there is still no integration with any payment rail.

Enterprises evaluating PACT for regulatory compliance need: (1) a receipt dashboard where compliance officers can see what agents did, (2) monetary budget enforcement so CFOs can set spending caps, (3) SDK maturity so engineering teams can integrate without reading Rust source code. Land 5-10 design partners in healthcare and financial services -- the verticals with the tightest regulatory timelines -- and let their requirements drive hardening priorities. Protocol purity without users is a research project, not infrastructure.

### Perspective C: The Ecosystem Strategist

Both arguments miss the adoption bottleneck. PACT currently sits under MCP via the adapter. That is one integration point with one protocol. The agent ecosystem is fragmenting: Google A2A for agent-to-agent communication, MCP for tool access, ACP/x402/AP2 for payments, AIUC for certification. Every enterprise will use multiple protocols. PACT's strategic position is not "replace MCP" -- it is "be the trust layer that sits under everything."

The MCP adapter already proves the model. An A2A adapter would let PACT mediate agent-to-agent interactions with the same capability enforcement and receipt signing. A payment rail bridge would let PACT receipts drive settlement workflows on Stripe ACP or x402 without PACT needing to move money itself. Each adapter makes PACT more valuable without requiring PACT to compete directly with any established protocol.

The flywheel described in VISION.md depends on receipt volume. Receipt volume depends on adoption surface area. Adoption surface area depends on how many protocols PACT can sit under. Building adapters is the highest-leverage work for the flywheel because each adapter multiplies the receipt generation rate without requiring new PACT-native deployments.

### Where They Agreed

All three perspectives agreed on four points:

1. **Merkle commitment must ship before any claim about tamper-evident receipts is used in sales or regulatory filings.** The code exists. Wiring it in is weeks of work, not months. There is no excuse for the gap.

2. **Monetary budgets are the single most important product feature.** Every stakeholder -- regulators, CFOs, insurers, developers -- understands "this agent can spend up to $500." Invocation-count budgets are a technical primitive. Monetary budgets are a product primitive.

3. **SDK maturity determines adoption velocity.** The Rust implementation is strong but Rust-only adoption is a ceiling. TS and Python SDKs need to reach production quality.

4. **The regulatory deadlines (June/August 2026) are real forcing functions.** PACT needs a compliance-ready story before those dates, even if the full vision is not realized.

### Where They Disagreed

The core disagreement was sequencing:

- **A** wanted: Merkle + DPoP + proofs, then monetary budgets, then ecosystem.
- **B** wanted: monetary budgets + dashboard + design partners, then Merkle (because partners would demand it), then ecosystem.
- **C** wanted: A2A adapter + payment bridges, then Merkle (because volume justifies the investment), then monetary budgets (because the payment rails handle money).

**Resolution:** The debate resolved when B conceded that Merkle commitment is small enough to parallelize with monetary budgets rather than defer, A conceded that DPoP implementation and Lean 4 proof completion can follow monetary budgets without compromising security (subject binding already prevents token replay between principals), and C conceded that the A2A adapter depends on A2A protocol stability, making it a should-do rather than a must-do for Q2/Q3. That condition is now satisfied enough for a thin but real A2A v1.0.0 control surface, but deeper task lifecycle, push notification, non-header auth, and federation work still belongs in the later roadmap.

The synthesis: **ship Merkle commitment and monetary budgets together in Q2 2026** (before the Colorado deadline), **ship the capability lineage index, receipt analytics, and compliance dashboard in Q3 2026** (before the EU deadline), **ship SDK production releases and the A2A adapter in Q4 2026**, **ship local reputation and reputation-gated issuance in Q1 2027**, and **ship portable trust credentials plus economic integration in Q2 2027**.

---

## Roadmap

### Principles

These rules govern the roadmap. When two priorities conflict, the higher-numbered principle yields to the lower-numbered one.

1. **Security claims must be backed by shipping code.** No feature described in marketing or regulatory filings that is not wired into the runtime.
2. **Regulatory deadlines are hard constraints.** Colorado (June 2026) and EU (August 2026) compliance stories must be ready before those dates.
3. **Adoption requires product surface, not protocol surface.** SDKs, dashboards, and documentation determine adoption speed.
4. **Every adapter multiplies receipt volume.** Ecosystem integration is leverage, not distraction.
5. **Formal verification is a moat, not a gate.** Proofs are strategically valuable but should not block product shipping.

---

### Q2 2026 (April -- June): Foundation for Trust and Economics

**Theme:** Wire the security foundation that backs PACT's claims, and ship the economic primitive that makes PACT useful for budget enforcement. Hit the Colorado AI Act deadline.

#### Must Do

| Deliverable | Description | Success Metric | Owner Area |
|-------------|-------------|----------------|------------|
| **Merkle receipt commitment** | Wire `pact-core::merkle` into the receipt pipeline. Every receipt batch gets a Merkle root and a kernel-signed checkpoint statement. Receipt store persists checkpoints. Verification API confirms inclusion against a published checkpoint/root. | Receipt inclusion proofs pass round-trip verification against signed checkpoints in all three SDK languages. | `pact-kernel`, `pact-core` |
| **Monetary budgets (single currency)** | Extend `ToolGrant` budget model from invocation counts to denominated currency amounts in a single currency (e.g., USD cents). Add `MonetaryAmount` type, `max_cost_per_invocation` and `max_total_cost` fields to `ToolGrant`, `try_charge_cost` to `BudgetStore` trait, and `ToolInvocationCost` for tool server cost reporting. Multi-currency and exchange-rate binding deferred to Q3/Q4. | Monetary budget enforcement demonstrated end-to-end: tool call with cost reporting, budget decrement in receipt metadata, denial on budget exhaustion. | `pact-core`, `pact-kernel`, `pact-guards` |
| **pact-core schema migration** | Remove `deny_unknown_fields` from `ToolGrant` and related serializable types across `pact-core` (18 instances across `capability.rs`, `receipt.rs`, `manifest.rs` -- including `CapabilityToken`, `CapabilityTokenBody`, `PactScope`, `DelegationLink`, `DelegationLinkBody`, and all receipt types). Add a versioned extension mechanism or switch to `#[serde(flatten)]` for forward compatibility. | Existing tests pass. New budget fields deserialize without breaking existing grants. Old kernels that have not upgraded gracefully reject tokens with unknown fields rather than crashing. | `pact-core` |
| **Colorado compliance story** | Document how PACT receipts satisfy Colorado SB 24-205 requirements for "records of the AI system's outputs and the basis for those outputs." | Published compliance mapping document. | `docs/` |

#### Should Do

| Deliverable | Description | Success Metric |
|-------------|-------------|----------------|
| **DPoP per-invocation proofs** | Implement proof-of-possession for capability token usage. Each invocation includes a signed DPoP proof bound to the request. ClawdStrike already ships useful proof-validation logic in `clawdstrike-brokerd/src/capability.rs`, but PACT still needs a PACT-specific proof message, a nonce replay cache, and SDK helpers. | DPoP proof generation and validation in Rust and at least one SDK, with replayed nonces rejected. |
| **Receipt query API** | Add a query interface to the receipt store: filter by capability, tool, time range, outcome, and budget impact. Agent-level queries depend on the native capability lineage index that follows in Q3. ClawdStrike's `control-api/src/routes/receipts.rs` contributes pagination, payload-limit, and verification patterns, but not a drop-in lineage model for PACT. | Query API returns correct results for tool receipts and child-request receipts in the existing test corpus. |
| **SDK hardening: TS and Python** | Move TS and Python SDKs from alpha to beta. Stabilize the client/session API. Add error handling and retry semantics. | Both SDKs used by at least one external integration without requiring Rust source code access, and both pass the live conformance waves they claim to support. |
| **Velocity controls** | Add `MaxSpendPerWindow` and `MaxInvocationsPerWindow` constraints to the guard pipeline. Enables rate-limiting agent spending within time windows. ClawdStrike's token bucket implementation in `clawdstrike/src/async_guards/rate_limit.rs` can shorten the implementation, but PACT still needs synchronous deny semantics and per-agent/per-grant window accounting. | Velocity guard denies requests that exceed configured invocation or spend windows. |

#### Could Do

| Deliverable | Description |
|-------------|-------------|
| **Lean 4 BEq sorry closure** | Resolve the remaining `sorry` in the Monotonicity proof. |
| **Receipt export format** | Define a portable receipt export format (JSON lines or similar) for offline verification. |

#### Decision Gate: Exit Q2

Before entering Q3, the following must be true:
- Merkle receipt commitment and signed checkpoint publication are wired and tested, not just coded.
- Monetary budget enforcement works end-to-end with signed receipts showing budget impact.
- The Colorado compliance mapping is reviewed by at least one person with regulatory domain knowledge.

---

### Q3 2026 (July -- September): Compliance Surface and Operational Visibility

**Theme:** Ship the operational tools that let enterprises deploy PACT for EU AI Act compliance. Make receipts visible and actionable.

#### Must Do

| Deliverable | Description | Success Metric | Owner Area |
|-------------|-------------|----------------|------------|
| **Capability lineage index** | Persist issued capability snapshots keyed by `capability_id`, including subject, issuer, grants, and delegation metadata. Provide a deterministic local join path from receipt to agent identity and grant context. | Given an agent public key or capability ID, the system can resolve all related receipts and delegation context without replaying external issuance logs. | `pact-kernel`, `pact-core` |
| **Receipt dashboard** | A web-based receipt viewer: browse receipts, filter by agent/tool/outcome/time, inspect delegation chains, view budget consumption. Read-only. | Dashboard renders the receipt corpus from a live PACT deployment. Non-engineer stakeholders can answer "what did agent X do last Tuesday?" without CLI access. | New package or standalone tool |
| **EU AI Act compliance story** | Document how PACT satisfies Article 19 traceability requirements for high-risk AI systems. Map receipt retention to the "minimum period proportionate to intended purpose" requirement. | Published compliance mapping. Receipt retention policy configurable and documented. | `docs/` |
| **Receipt retention and rotation** | Configurable receipt retention policies. Time-based and size-based rotation. Archived receipts remain verifiable via Merkle proofs. | Retention policy enforced in tests. Archived receipts verify against stored Merkle roots. | `pact-kernel`, receipt store |
| **SDK production release: TypeScript** | Promote `pact-ts` from beta to 1.0. Stable API contract. Published to npm. Semantic versioning. | npm package published. Breaking changes require major version bump. At least one external consumer. Live JS conformance lanes stay green in CI. | `packages/sdk/pact-ts` |

#### Should Do

| Deliverable | Description | Success Metric |
|-------------|-------------|----------------|
| **SDK production release: Python** | Promote `pact-py` from beta to 1.0. Published to PyPI. | PyPI package published. Live Python conformance lanes stay green in CI. |
| **Receipt analytics API** | Aggregate receipt data: reliability scores, compliance rates, budget utilization by agent/tool/time period. | Analytics API returns correct aggregates for the test receipt corpus. |
| **AIUC-1 certification mapping** | Map PACT capabilities to AIUC-1 certification requirements. Document the overlap and any gaps. | Published mapping document. |
| **DPoP completion** | If not completed in Q2, finish DPoP implementation across all SDKs. | DPoP proofs validated on every invocation in CI, with stale or replayed nonces rejected. |
| **Receipt pipeline performance baseline** | Benchmark the receipt pipeline (signing, storage, Merkle commitment) under load. Establish receipts/second baseline for future optimization. | Published benchmark results with methodology. |
| **Tool manifest pricing metadata** | Add pricing fields to `ToolDefinition` in `pact-manifest` (pricing model, base price, unit price). Tool servers advertise costs so agents can budget before invocation. | At least one example tool server publishes pricing in its manifest. |
| **ClawdStrike dependency restructure** | Begin migrating ClawdStrike to import `pact-core` as a workspace dependency, replacing its internal `hush-core` types with canonical PACT types. This establishes the "powered by PACT" relationship where ClawdStrike consumes PACT as a library rather than maintaining parallel type definitions. | ClawdStrike compiles against `pact-core` for capability, receipt, and scope types. |
| **Receipt export to SIEM** | Export receipts to enterprise SIEM platforms. ClawdStrike has 6 production-ready exporters (Splunk, Elastic, Datadog, Sumo Logic, Webhooks, Alerting) that can be ported as a `pact-siem` crate in ~2 weeks. Promoted from Could Do because the existing code makes this adaptation work rather than greenfield. | At least 2 SIEM exporters functional and tested. |

#### Could Do

| Deliverable | Description |
|-------------|-------------|
| **Policy simulation mode** | Dry-run mode that evaluates policies against historical receipts without live tool invocation. |

#### Decision Gate: Exit Q3

Before entering Q4, the following must be true:
- A deterministic local join path exists from receipt -> capability subject -> grant context.
- The receipt dashboard is deployed and usable by non-engineers.
- TypeScript SDK is at 1.0, published, and green in live conformance CI.
- At least one compliance mapping (Colorado or EU) has been reviewed by someone with regulatory knowledge.
- At least 2 external parties have evaluated PACT for a real use case (design partner pipeline started).

---

### Q4 2026 (October -- December): Ecosystem Expansion

**Theme:** Make PACT the trust layer under multiple protocols. Convert design partners to deployments.

#### Must Do

| Deliverable | Description | Success Metric | Owner Area |
|-------------|-------------|----------------|------------|
| **SDK production release: Python and Go** | Python at 1.0 on PyPI. Go at 1.0. Both with stable API contracts. | Published packages. At least one external consumer each. Live Python and Go conformance lanes stay green in CI. | `packages/sdk/` |
| **Payment rail bridge: truthful settlement flow** | A reference integration that bridges PACT receipts to at least one payment rail (Stripe ACP or x402) using truthful execution semantics: prepaid rails settle before invocation; post-priced rails use hold/capture or explicit pending-settlement state. | End-to-end demo: PACT-mediated tool call produces truthful allow/deny receipts plus accurate settlement state linked to the payment rail. | New integration package |
| **Design partner program** | Formal design partner agreements with 3-5 organizations. At least 2 in regulated verticals (healthcare, financial services). | Signed agreements. Regular feedback sessions. At least one partner running PACT in a staging or pre-production environment. | Business |

#### Should Do

| Deliverable | Description | Success Metric |
|-------------|-------------|----------------|
| **A2A trust adapter** | PACT sits as the capability and receipt layer for Google A2A agent-to-agent interactions. `pact-a2a-adapter` now covers A2A v1.0.0 Agent Card discovery, blocking `SendMessage`, `SendStreamingMessage`, follow-up `GetTask`, follow-up `SubscribeToTask`, follow-up `CancelTask`, push-notification config create/get/list/delete, fail-closed bearer/HTTP Basic/API-key auth negotiation from Agent Card metadata, fail-closed `stateTransitionHistory` enforcement for `historyLength` usage, fail-closed task/status lifecycle payload validation, OAuth2 client-credentials and OpenID Connect token acquisition, truthful mTLS transport with custom root CA support, and tenant-aware HTTP path shaping over both `JSONRPC` and `HTTP+JSON`; remaining work is custom auth beyond the shipped matrix, federation depth, and production hardening. | An A2A agent-to-agent interaction produces PACT receipts with correct capability scoping and delegation tracking. | New `pact-a2a-adapter` crate |
| **Cross-org delegation** | Federated capability delegation across organizational boundaries. Per-org policy enforcement. Bilateral receipt sharing. The bilateral sharing substrate is now real through signed federation policies plus constrained evidence-export packages, and those packages can now be generated live over trust-control and consumed back into another trust-control node through verified `pact evidence import`. The live issuance lane is now also real through challenge-bound passport presentation consumption, signed federated delegation-policy documents, and parent-bound `--upstream-capability-id` continuation, so a new local delegation anchor can bridge to an imported upstream capability instead of collapsing the chain into a fake local root. Remaining work is broader remote receipt analytics/operator surfaces and richer cross-org identity/admin integration, not first multi-hop chain reconstruction itself. | Two organizations can delegate capabilities to each other's agents with correct attenuation and receipt generation. |
| **Identity federation** | Integration with at least one enterprise identity provider (Okta, Auth0, or Azure AD) for mapping organizational identities to PACT principals. The current alpha now covers bearer-authenticated `serve-http` sessions via stable principal-to-subject derivation, startup-time OIDC discovery, JWKS bootstrap for `EdDSA`, RSA, and `ES256`/`ES384`, explicit OAuth2 token introspection for opaque bearer tokens, provider-aware principal mapping for Generic/Auth0/Okta/Azure AD claim shapes, and propagation of normalized enterprise identity metadata (`clientId`, `objectId`, `tenantId`, `organizationId`, `groups`, `roles`) into the admin trust surface; remaining work is broader federation surfaces plus SCIM/SAML and provider-admin integration. | PACT agents authenticated via enterprise IdP produce correctly bound capability tokens. |
| **Lean 4 proof completion** | Close all remaining `sorry` declarations. Publish proof artifacts as part of the release. | `lake build` completes with zero `sorry` warnings. |
| **Multi-currency budgets** | Extend monetary budgets to support multiple currencies. Exchange-rate binding at grant issuance. | Tool server priced in EUR, agent budgeted in USD, kernel enforces correct conversion. |

#### Could Do

| Deliverable | Description |
|-------------|-------------|
| **PACT Certify alpha** | A certification process for tool servers: attest that a tool correctly implements the PACT contract and produces well-formed receipts. |
| **Rust SDK stabilization** | Publish `pact-core` and `pact-kernel` to crates.io with stable API guarantees. |

#### Decision Gate: Exit Q4

Before entering 2027, the following must be true:
- At least one payment rail bridge works end-to-end in a demo environment.
- At least 3 design partners are actively evaluating PACT.
- All SDKs (TS, Python, Go) are at 1.0 and green in live conformance CI.
- The protocol spec has been updated to reflect shipped reality (Merkle commitment/checkpoints, monetary budgets, DPoP).
- If A2A adapter was shipped: at least one A2A interaction produces valid PACT receipts.

---

### Q1 2027 (January -- March): Reputation Foundation

**Theme:** Turn persisted receipt and capability-lineage data into local reputation signals. Ship reputation-gated issuance before tackling portable cross-org credentials.

#### Must Do

| Deliverable | Description | Success Metric | Owner Area |
|-------------|-------------|----------------|------------|
| **Receipt-derived local reputation scores** | Compute behavioral metrics from persisted receipt data, the capability lineage index, and per-grant budget usage joins: reliability, compliance, scope discipline, delegation hygiene, budget adherence, and history depth. Missing metrics are treated as unknown, not zero. | Reputation scores are computed for agents in the design partner corpus and are deterministic and reproducible from local persisted state. | New `pact-reputation` crate or module |
| **HushSpec reputation extensions and graduated authority** | Extend `pact-policy` to express reputation weights, tiers, and promotion/demotion rules. Capability issuance reads the current local reputation tier before granting TTL, delegation depth, and budget ceilings. | Tier definitions parse and compile, and at least one deployment enforces reputation-gated issuance in staging or production. | `pact-policy`, capability authority |
| **Production deployment support** | At least 2 design partners running PACT in production. Operational runbook. On-call escalation documentation. Incident response playbook. | Production deployments with SLA commitments. | Ops, docs |
| **PACT Certify v1** | Certification program for tool servers. Automated conformance check. Certification credential published as a verifiable attestation. | Certification process designed, tooling built, and at least 1 tool server certified as proof-of-concept. | New service |

#### Should Do

| Deliverable | Description | Success Metric |
|-------------|-------------|----------------|
| **did:pact DID method** | Define and register the `did:pact` DID method. Agent public keys resolve to DID Documents with verification methods and receipt log service endpoints. This is the required identity foundation for portable passports, but not for local scoring. | DID resolution works for agent and kernel identifiers. |
| **Agent Passport alpha** | Single-issuer W3C Verifiable Credential bundle for agent behavioral attestations, including offline verification, policy evaluation, filtered presentation, and challenge-bound holder proof. Cross-org portability remains limited until `did:pact`, verifier libraries, and multi-issuer composition stabilize. | A relying party verifies a passport issued by one Kernel operator and completes a challenge-bound presentation flow without custom glue code. |
| **Receipt-based anomaly detection** | Flag agents whose behavioral patterns deviate from historical baselines: sudden tool usage changes, budget consumption spikes, delegation depth increases. | Anomaly detection triggers on synthetic test data with known anomalies. |
| **Multi-payment-rail support** | Extend the payment rail bridge to cover at least 2 payment protocols (e.g., both Stripe ACP and x402). | Both bridges work end-to-end. |

#### Could Do

| Deliverable | Description |
|-------------|-------------|
| **Insurance data export** | Export receipt and reputation data in a format suitable for actuarial analysis by insurers. |
| **Anti-collusion detection** | Receipt pattern analysis to detect agent collusion in marketplace settings. |

#### Decision Gate: Exit Q1

Before entering Q2 2027, the following must be true:
- Reputation scores are computed from real receipt data, not synthetic data only.
- Reputation-gated capability issuance is enforced in at least one real deployment.
- At least 2 production deployments exist.

---

### Q2 2027 (April -- June): Portable Trust and Economic Integration

**Theme:** Make trust portable across organizations and connect receipt-backed authorization to real settlement infrastructure.

#### Must Do

| Deliverable | Description | Success Metric | Owner Area |
|-------------|-------------|----------------|------------|
| **Agent Passport v1 + `did:pact`** | Portable W3C Verifiable Credential format for agent behavioral attestations, backed by the `did:pact` DID method and verifier libraries. | An Agent Passport is issued, verified, and consumed by a different organization in a cross-org delegation or access-grant scenario. | New module |
| **Receipt-linked settlement** | Production-grade integration where PACT receipts with monetary budget impact drive settlement on connected payment rails without falsifying tool outcomes. Payment failures before execution deny the call; post-execution failures are represented as pending/failed settlement state tied to an allow receipt and reconciliation flow. | At least one design partner uses receipt-linked settlement in production or late-stage staging, and receipts truthfully distinguish execution outcome from settlement outcome. | Integration package |
| **Cost attribution across delegation chains** | Multi-hop delegation chains produce receipts that enable end-to-end cost attribution. Each hop's budget impact is traceable to the original principal. | Cost attribution report generated from a real multi-agent delegation scenario. | `pact-kernel`, `pact-core` |
| **Regulatory compliance evidence package** | A turnkey export that produces the evidence package a regulated enterprise needs for Colorado AI Act and EU AI Act compliance audits. Includes receipt logs, Merkle proofs, policy configurations, and retention documentation. | Evidence package generated and validated against the compliance mapping documents. | Tooling |

#### Should Do

| Deliverable | Description | Success Metric |
|-------------|-------------|----------------|
| **PACT Certify scale: 5+ certified tool servers** | Expand certification program from proof-of-concept to at least 5 certified tool servers. Publish certification registry. | 5+ entries in the public certification registry. |
| **Agent insurance data feed** | Structured data feed for insurers: per-agent behavioral metrics, budget adherence history, violation records. Compatible with at least one insurer's data ingestion format (target: AIUC). | Insurer confirms the feed format meets their underwriting data requirements. |
| **Marketplace trust primitives** | PACT as the trust layer for agent marketplaces: capability-scoped bids, receipt-verified task completion, reputation-gated access. | Reference marketplace implementation using PACT primitives. |
| **Protocol specification v2** | Updated protocol specification reflecting all shipped features: Merkle commitment/checkpoints, monetary budgets, DPoP, reputation scores, Agent Passports, settlement bridges. | Spec published. No delta between spec and shipping code for covered features. |
| **Conformance test suite release** | Open-source the cross-language conformance test suite (JS, Python, Rust peers, 5 waves) as a standalone community asset. Enables independent PACT implementations and validates interoperability. | Published on GitHub. At least one external party runs the suite. |

#### Could Do

| Deliverable | Description |
|-------------|-------------|
| **Parametric insurance prototype** | Automatic payout triggered by receipt-detected policy violations. |
| **Browser-based SDK** | WASM-based PACT client for browser environments. |

---

### Q3-Q4 2027 (July -- December): Scale and Standards

**Theme:** Scale from design partners to broad adoption. Position PACT receipts as a standard.

#### Must Do

| Deliverable | Description | Success Metric |
|-------------|-------------|----------------|
| **10+ production deployments** | Expand from design partners to broader adoption. | 10 organizations running PACT in production. |
| **Standards body engagement** | Submit PACT receipt format as a proposed standard to an appropriate body (IETF, W3C, or OpenSSF). Engage with NIST AI Agent Standards Initiative (building on any earlier RFI responses). | Formal submission accepted for review. |
| **PACT Certify scale** | 50+ certified tool servers. Certification process fully automated. | Published certification registry with 50+ entries. |
| **Performance at scale** | Receipt pipeline handles 10,000+ receipts/second per node. Merkle commitment does not become a bottleneck. | Load test results published. |

#### Should Do

| Deliverable | Description | Success Metric |
|-------------|-------------|----------------|
| **Reputation network federation** | Decentralized reputation scores that travel with agents across organizational boundaries. | Cross-org reputation queries work without centralized coordination. |
| **Multi-region receipt anchoring** | Receipt Merkle roots anchored to a public transparency log or blockchain for geographic redundancy and public verifiability. | Anchoring demonstrated with at least one public log. |

---

## What We Cut and Why

The following items appeared in various planning documents but are explicitly deprioritized in this roadmap:

| Item | Why Cut | When It Could Return |
|------|---------|---------------------|
| **Full OS sandbox manager** | Root enforcement is the right abstraction level for v1. Full sandboxing is a different product. | 2028, if enterprise demand materializes. |
| **Multi-region Byzantine consensus** | The HA leader/follower model serves current scale. Byzantine tolerance is premature. | When PACT mediates cross-org transactions where principals do not trust each other's infrastructure. |
| **WASM/PyO3/CGO native acceleration** | Pure remote-edge SDKs are the right first step. Native acceleration adds release burden without proportional adoption value at current scale. | After SDK 1.0 releases prove stable and users request performance improvements. |
| **Protocol-level anti-collusion mechanisms** | Important for agent marketplaces but premature. Detection (via receipt analysis) comes first; prevention is a research problem. | Q3 2027 earliest, after marketplace trust primitives prove the detection layer. |
| **Complete theorem-prover coverage of the full protocol** | P1-P5 proofs cover the core security properties. Proving the full protocol (including transport, session lifecycle, and economic extensions) is a multi-year formal methods program. | Continuous background work; not a shipping gate. |
| **Custom payment rail** | PACT is the authorization/attestation layer, not a payment rail. Building a payment rail would compete with Stripe, Coinbase, and Visa rather than complement them. | Never, unless the bridge model proves architecturally insufficient. |
| **Merging ClawdStrike into PACT** | ClawdStrike is a policy engine product; PACT is a vendor-neutral protocol. They must remain architecturally separate. The integration direction is ClawdStrike becoming "powered by PACT" -- importing `pact-core` as a dependency -- not PACT absorbing ClawdStrike's policy semantics. ClawdStrike code ports (DPoP, receipt query, rate limiting, SIEM exporters) accelerate Q2-Q3 delivery, but the ported code is adapted to PACT's type system and stripped of ClawdStrike-specific policy coupling. PACT stays vendor-neutral; ClawdStrike stays a first-party consumer. | Never. The boundary is architectural, not temporal. |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **A2A protocol instability** | Medium | High -- A2A adapter work wasted if Google changes the spec materially | Defer A2A adapter to Q4 2026. Monitor A2A spec stability. Design the adapter as a thin layer so rework is bounded. |
| **SDK adoption slower than projected** | Medium | Medium -- delays design partner pipeline | Prioritize TS SDK (largest developer population). Ship working examples, not just API docs. Offer white-glove integration support for first 5 partners. |
| **Payment rail integration complexity** | High | Medium -- delays economic integration story | Start with the simplest rail (x402: HTTP 402 + on-chain verification). Keep the bridge thin. Model settlement truthfully via prepaid, hold/capture, or explicit pending-settlement receipts. Do not build payment infrastructure. |
| **DPoP semantic gap / replay protection** | Medium | High -- incomplete proof-of-possession story or false security claims | Treat ClawdStrike's broker DPoP code as source material for validation logic, not a drop-in port. Do not mark DPoP complete until PACT-specific proof binding, nonce replay storage, and SDK helper coverage ship. |
| **Reputation data substrate gap** | Medium | High -- Q1 2027 reputation work stalls or produces non-reproducible scores | Ship the capability lineage index and per-grant join path before reputation implementation begins. Do not promise agent-level analytics or budget-discipline scoring without the local join substrate. |
| **Regulatory timeline slip** | Low | Low -- gives more time, does not change priorities | Roadmap is sequenced for the published dates. A delay helps rather than hurts. |
| **Design partner churn** | Medium | High -- undermines adoption story | Start with 5-8 partners expecting 40-60% conversion. Select partners with genuine regulatory pressure, not curiosity-driven evaluation. |
| **Merkle commitment performance at scale** | Low | Medium -- receipt pipeline throughput regression | Batch Merkle commitment (e.g., commit every 100 receipts or every 5 seconds, whichever comes first). Profile before optimizing. |
| **Q2 scope overload** | Medium | High -- Colorado deadline missed | Q2 has 4 Must Do items including the 18-instance `deny_unknown_fields` migration and monetary budgets (estimated 5-7 weeks alone). ClawdStrike code ports reduce pressure only on parts of the Should Do tier by contributing validation logic and implementation patterns; they do not eliminate PACT-native design work. If scope pressure mounts, cut DPoP, receipt query, and velocity work to Q3 before compromising Q2 Must Do delivery. |
| **NIST standards window** | Low | Medium -- missed opportunity | NIST's AI Agent Standards Initiative issued RFIs in early 2026. PACT should submit comments before the April 2, 2026 deadline for the identity/authorization RFI. A response costs ~1 week and positions PACT in the standards conversation early. |

---

## Quarterly Summary

| Quarter | Theme | Key Output |
|---------|-------|------------|
| **Q2 2026** | Foundation | Merkle commitment/checkpoints + monetary budgets + Colorado compliance |
| **Q3 2026** | Compliance surface | Capability lineage index + receipt dashboard + EU compliance + TS SDK 1.0 |
| **Q4 2026** | Ecosystem expansion | Payment bridge + all SDKs at 1.0 + design partners + A2A adapter (if stable) |
| **Q1 2027** | Reputation foundation | Local reputation + graduated authority + PACT Certify + production deployments |
| **Q2 2027** | Portable trust + economic integration | Agent Passports + receipt-linked settlement + cost attribution + compliance evidence |
| **Q3-Q4 2027** | Scale and standards | 10+ deployments + standards submission + performance at scale |

---

## How to Read This Roadmap

- **Must Do** items are commitments. If they slip, the quarter has failed and downstream quarters must be replanned.
- **Should Do** items are high-value work that ships if capacity allows. They become Must Do items in the following quarter if they slip.
- **Could Do** items are opportunistic. They ship if someone has bandwidth and motivation. They are never promoted to Must Do without a new decision.
- **Decision Gates** are hard checkpoints. The team does not start the next quarter's Must Do work until the gate conditions are met. If a gate is not met, the team stays on the current quarter's work until it is.

This roadmap will be reviewed and updated at each quarterly gate. The Q3-Q4 2027 section is intentionally less detailed because its shape depends on Q1-Q2 2027 outcomes.
