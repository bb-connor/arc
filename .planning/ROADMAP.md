# Roadmap: PACT

## Milestones

- [x] **v1.0 Closing Cycle** - Phases 1-6 (shipped 2026-03-20)
- [ ] **v2.0 Agent Economy Foundation** - Phases 7-12 (in progress)

## Phases

<details>
<summary>v1.0 Closing Cycle (Phases 1-6) - SHIPPED 2026-03-20</summary>

### Phase 1: E9 HA Trust-Control Reliability
**Goal**: Make clustered trust-control deterministic enough that workspace and CI runs stop failing on leader/follower visibility races.
**Depends on**: Nothing (current closing-cycle entry phase)
**Requirements**: [HA-01, HA-02, HA-03, HA-04]
**Success Criteria** (what must be TRUE):
  1. Repeated workspace and targeted trust-cluster runs no longer flake on leader-side budget visibility.
  2. Forwarded writes return success only after the documented visibility guarantee is actually satisfied.
  3. Authority, revocation, receipt, and budget state remain correct across leader failover.
  4. Cluster status surfaces enough state to localize routing, cursor, and convergence failures quickly.
**Plans**: 4 plans

Plans:
- [x] 01-01: Reproduce the current trust-cluster flake and add observability for leader, follower, and cursor state.
- [x] 01-02: Freeze and implement the control-plane write visibility contract for forwarded writes.
- [x] 01-03: Harden replication ordering and cursor semantics across budget, authority, receipt, and revocation state.
- [x] 01-04: Add failover, convergence, and repeat-run coverage that proves the cluster is stable under load.

### Phase 2: E12 Security Boundary Completion
**Goal**: Turn negotiated roots into enforced runtime boundaries for filesystem-shaped tools and filesystem-backed resources.
**Depends on**: Phase 1
**Requirements**: [SEC-01, SEC-02, SEC-03, SEC-04]
**Success Criteria** (what must be TRUE):
  1. Filesystem-shaped tool calls outside allowed roots are denied with signed evidence.
  2. Filesystem-backed resource reads outside allowed roots are denied with signed evidence.
  3. Root normalization rules are explicit and consistent across the supported transports.
  4. Missing or stale roots never silently expand access.
**Plans**: 4 plans

Plans:
- [x] 02-01: Freeze the root normalization model and threat boundaries for filesystem-shaped access.
- [x] 02-02: Enforce roots for tool calls with path-bearing arguments and fail-closed receipts.
- [x] 02-03: Enforce roots for filesystem-backed resources while preserving non-filesystem resource behavior.
- [x] 02-04: Add cross-transport tests and docs that make the enforced boundary explicit.

### Phase 3: E10 Remote Runtime Hardening
**Goal**: Make the hosted remote MCP runtime reconnect-safe, resumable where intended, and scalable beyond the current subprocess ownership shape.
**Depends on**: Phase 2
**Requirements**: [REM-01, REM-02, REM-03, REM-04]
**Success Criteria** (what must be TRUE):
  1. Remote sessions follow one documented reconnect and resume contract.
  2. GET-based SSE coverage exists and works against the compatibility surface.
  3. Stale-session cleanup, drain, and shutdown behavior are deterministic and test-covered.
  4. Hosted runtime ownership no longer depends on one subprocess per session in all serious deployments.
**Plans**: 4 plans

Plans:
- [x] 03-01: Specify resumability, reconnect rules, and terminal states for remote sessions.
- [x] 03-02: Implement GET/SSE stream support and align POST/GET stream ownership behavior.
- [x] 03-03: Expand the hosted ownership model for wrapped and native providers.
- [x] 03-04: Add lifecycle diagnostics, cleanup behavior, and operational docs for hosted runtime use.

### Phase 4: E11 Cross-Transport Concurrency Semantics
**Goal**: Make task ownership, stream ownership, cancellation, and late async completion behave the same way across direct, wrapped, stdio, and remote paths.
**Depends on**: Phase 3
**Requirements**: [CON-01, CON-02, CON-03, CON-04]
**Success Criteria** (what must be TRUE):
  1. One ownership model describes active work, stream emission, and terminal state across transports.
  2. `tasks-cancel` no longer remains `xfail` in the remote story.
  3. Late async completion no longer depends on request-local bridges surviving accidentally.
  4. Cancellation races produce deterministic receipts and terminal outcomes across all supported paths.
**Plans**: 4 plans

Plans:
- [x] 04-01: Freeze the transport-neutral ownership state machine for work, streams, and terminal state.
- [x] 04-02: Remove transport-specific task lifecycle edge cases, including the remote `tasks-cancel` gap.
- [x] 04-03: Normalize cancellation race semantics and nested parent/child linkage.
- [x] 04-04: Add durable async completion sources and late-event coverage for native and wrapped paths.

### Phase 5: E13 Policy and Adoption Unification
**Goal**: Give operators and adopters one clear policy story and one higher-level path into native PACT services.
**Depends on**: Phase 4
**Requirements**: [POL-01, POL-02, POL-03, POL-04]
**Success Criteria** (what must be TRUE):
  1. One policy authoring path is clearly documented as canonical.
  2. All shipped guards are reachable through the supported configuration surface.
  3. Wrapped-MCP-to-native migration guidance and examples are maintained and evidence-backed.
  4. At least one higher-level native authoring surface exists and is test-covered.
**Plans**: 4 plans

Plans:
- [x] 05-01: Freeze the supported policy contract and align README, CLI messaging, and docs around it.
- [x] 05-02: Expose the full shipped guard surface through the supported path with regression coverage.
- [x] 05-03: Ship migration guides and examples for wrapped-to-native adoption.
- [x] 05-04: Add a higher-level native authoring surface that covers the core PACT primitives coherently.

### Phase 6: E14 Hardening and Release Candidate
**Goal**: Turn the closing-cycle epics into a release candidate with explicit guarantees, limits, and go/no-go evidence.
**Depends on**: Phase 5
**Requirements**: [REL-01, REL-02, REL-03, REL-04]
**Success Criteria** (what must be TRUE):
  1. Workspace build, lint, and test gates are repeatable in CI and local qualification runs.
  2. Failure-mode, limits, and guarantee docs accurately describe the supported surface.
  3. Examples, conformance coverage, and release docs tell one coherent story.
  4. No remaining post-review finding is deferred into an undefined hardening bucket.
**Plans**: 4 plans

Plans:
- [x] 06-01: Build the release qualification matrix covering gates, limits, and unresolved findings.
- [x] 06-02: Add failure-mode, regression, and qualification coverage for the final supported surface.
- [x] 06-03: Publish release docs covering guarantees, non-goals, migration path, and extension policy.
- [x] 06-04: Run the final milestone audit and capture the release-candidate go/no-go decision.

</details>

---

## v2.0 Agent Economy Foundation

**Milestone Goal:** Transform PACT from a security protocol into economic infrastructure for autonomous agent systems. Ship Merkle-committed receipts, monetary budgets, compliance-ready tooling, and the data substrate for agent reputation. Hit Colorado (June 2026) and EU AI Act (August 2026) regulatory deadlines.

**Phase Numbering:**
- Integer phases (7-12): Planned v2.0 milestone work
- Decimal phases (7.1, 7.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 7: Schema Compatibility and Monetary Foundation** - Remove deny_unknown_fields from all 18 pact-core types and add monetary budget types to ToolGrant. (completed 2026-03-22)
- [x] **Phase 8: Core Enforcement** - Wire monetary budget enforcement, Merkle checkpoint batching, and velocity guard into the kernel execution path. (completed 2026-03-22)
- [ ] **Phase 9: Compliance and DPoP** - Ship Colorado and EU AI Act compliance documents against verified code, add receipt retention, and add DPoP proof-of-possession.
- [x] **Phase 10: Receipt Query API and TypeScript SDK 1.0** - Make receipts queryable via API and publish the TypeScript SDK at stable 1.0. (completed 2026-03-23)
- [x] **Phase 11: SIEM Integration** - Ship pact-siem crate with at least 2 exporters for enterprise security stack integration. (completed 2026-03-23)
- [ ] **Phase 12: Capability Lineage Index and Receipt Dashboard** - Build the agent-centric lineage index and the compliance officer receipt dashboard on top of it.

## Phase Details

### Phase 7: Schema Compatibility and Monetary Foundation
**Goal**: pact-core types tolerate unknown fields and carry monetary budget primitives, unblocking all subsequent v2.0 wire-format additions.
**Depends on**: Phase 6 (v1.0 complete)
**Requirements**: SCHEMA-01, SCHEMA-02, SCHEMA-03
**Success Criteria** (what must be TRUE):
  1. A capability token produced by a v1.0 kernel is accepted by a v2.0 kernel without deserialization errors.
  2. A v2.0 kernel token containing new fields is accepted by a v1.0 kernel without deserialization errors.
  3. ToolGrant fields max_cost_per_invocation and max_total_cost are present and round-trip correctly via canonical JSON.
  4. Attenuation enum variants ReduceCostPerInvocation and ReduceTotalCost serialize and deserialize correctly.
  5. A cross-version round-trip test passes in CI covering pre-existing SQLite databases.
**Plans**: 2 plans

Plans:
- [x] 07-01: Remove deny_unknown_fields from all 18 serialized types in pact-core and add forward-compatibility test fixtures.
- [x] 07-02: Add MonetaryAmount type, monetary budget fields to ToolGrant, and cost-reduction Attenuation variants with is_subset_of enforcement.

### Phase 8: Core Enforcement
**Goal**: Monetary budget limits, Merkle-committed receipt batches, and velocity throttling are all enforced at kernel evaluation time.
**Depends on**: Phase 7
**Requirements**: SCHEMA-04, SCHEMA-05, SCHEMA-06, SEC-01, SEC-02, SEC-05
**Success Criteria** (what must be TRUE):
  1. An invocation that would exceed max_cost_per_invocation or max_total_cost is denied with a signed receipt recording the denial reason.
  2. Tool servers can report invocation cost and that cost is recorded in FinancialReceiptMetadata on the signed receipt.
  3. A batch of 100 receipts produces a Merkle root and signed kernel checkpoint statement; a single receipt's inclusion proof verifies against it.
  4. An agent that exceeds a configured invocation or spend window is denied by the velocity guard without kernel panics or executor nesting.
  5. The monetary HA overrun bound under split-brain is explicitly documented and covered by a named concurrent-charge test.
**Plans**: 4 plans

Plans:
- [ ] 08-01-PLAN.md -- Monetary budget enforcement: FinancialReceiptMetadata, try_charge_cost in BudgetStore, ToolInvocationCost
- [ ] 08-02-PLAN.md -- Merkle checkpoint: KernelCheckpoint, batch signing, inclusion proofs, kernel_checkpoints table
- [ ] 08-03-PLAN.md -- Velocity guard: VelocityGuard with synchronous token bucket in pact-guards
- [ ] 08-04-PLAN.md -- Integration wiring: monetary enforcement, Merkle checkpointing, and velocity guard into kernel pipeline

### Phase 9: Compliance and DPoP
**Goal**: Colorado and EU AI Act compliance documents are filed against tested and shipped code, receipt retention is configurable, and DPoP proof-of-possession closes the stolen-token replay story.
**Depends on**: Phase 8
**Requirements**: COMP-01, COMP-02, COMP-03, COMP-04, SEC-03, SEC-04
**Success Criteria** (what must be TRUE):
  1. The Colorado SB 24-205 compliance document is published and references passing test artifacts for each claim (must ship before June 30, 2026).
  2. The EU AI Act Article 19 compliance document is published and references passing test artifacts for each claim (must ship before August 2, 2026).
  3. Receipt retention policy is configurable with both time-based and size-based rotation; archived receipts verify against stored Merkle checkpoint roots.
  4. A DPoP proof for invocation A is rejected when replayed for invocation B (cross-invocation replay test passes).
  5. A reused DPoP nonce within the configured TTL window is rejected by the nonce replay store.
**Plans**: 3 plans

Plans:
- [ ] 09-01-PLAN.md -- Receipt retention and rotation policy (time-based and size-based) with archived receipt Merkle verification.
- [ ] 09-02-PLAN.md -- DPoP proof-of-possession (PACT-native Ed25519 proof with LRU nonce replay store) and dpop_required on ToolGrant.
- [ ] 09-03-PLAN.md -- Colorado SB 24-205 and EU AI Act Article 19 compliance mapping documents against Phase 8 and 9 acceptance tests.

### Phase 10: Receipt Query API and TypeScript SDK 1.0
**Goal**: Receipts are queryable through a stable API and the TypeScript SDK is published at 1.0 with DPoP proof generation helpers.
**Depends on**: Phase 8 (receipt query requires signed receipts and financial metadata); Phase 9 for DPoP SDK helpers (DPoP kernel verifier must exist before client helpers are written)
**Requirements**: PROD-01, PROD-06
**Success Criteria** (what must be TRUE):
  1. An operator can filter receipts by capability, tool, time range, outcome, and budget impact via the receipt query API.
  2. The TypeScript SDK is published to npm at a stable 1.0 version with semantic versioning and documented error handling.
  3. TypeScript SDK DPoP proof generation helpers produce proofs that the Phase 9 kernel verifier accepts.
  4. The pact receipt list CLI subcommand returns paginated results using the same underlying query API.
**Plans**: 3 plans

Plans:
- [ ] 10-01-PLAN.md -- Implement receipt_query.rs in pact-kernel with ReceiptQuery struct, cursor-based pagination, and 7-filter SQL query.
- [ ] 10-02-PLAN.md -- Expose receipt query via GET /v1/receipts/query HTTP endpoint and pact receipt list CLI subcommand with JSON Lines output.
- [ ] 10-03-PLAN.md -- Harden TypeScript SDK to @pact-protocol/sdk 1.0.0: typed PactError hierarchy, DPoP proof generation, ReceiptQueryClient, build pipeline.

### Phase 11: SIEM Integration
**Goal**: Enterprise security teams can receive PACT receipt events in their existing SIEM via at least 2 tested exporters.
**Depends on**: Phase 10 (SIEM cursor-pull requires the receipt query API)
**Requirements**: COMP-05
**Success Criteria** (what must be TRUE):
  1. At least 2 SIEM exporters (Splunk HEC and Elasticsearch bulk) are functional, tested, and ship behind a feature flag in the pact-siem crate.
  2. The pact-kernel TCB has no HTTP client dependencies; all SIEM I/O is isolated in the pact-siem crate.
  3. Exporter failure does not block kernel execution; a bounded dead-letter queue absorbs export failures without unbounded memory growth.
  4. Receipt events delivered to a SIEM include FinancialReceiptMetadata when the source receipt carries monetary grants.
**Plans**: 3 plans

Plans:
- [ ] 11-01-PLAN.md -- pact-siem crate foundation: Exporter trait, SiemEvent, DeadLetterQueue, ExporterManager cursor-pull loop, workspace and feature flag integration.
- [ ] 11-02-PLAN.md -- Splunk HEC and Elasticsearch bulk exporters implementing Exporter trait with protocol-specific serialization.
- [ ] 11-03-PLAN.md -- Integration tests for both exporters, FinancialReceiptMetadata enrichment, DLQ bounded growth, and ExporterManager failure isolation.

### Phase 12: Capability Lineage Index and Receipt Dashboard
**Goal**: Operators and compliance officers can answer "what did agent X do?" through a web dashboard backed by a persistent capability lineage index.
**Depends on**: Phase 10 (dashboard reads receipt query API; lineage index requires stable receipt schema from Phase 8+)
**Requirements**: PROD-02, PROD-03, PROD-04, PROD-05
**Success Criteria** (what must be TRUE):
  1. Capability snapshots are persisted at issuance time and keyed by capability_id with subject, issuer, grants, and delegation metadata.
  2. Agent-centric receipt queries resolve through the lineage index without replaying issuance logs.
  3. A non-engineer stakeholder can open the receipt dashboard and filter by agent, tool, outcome, and time without CLI access.
  4. The dashboard shows delegation chain inspection and budget views for receipts with monetary grants.
**Plans**: TBD

Plans:
- [ ] 12-01: Implement capability_index.rs in pact-kernel with snapshot persistence at issuance and subject_key index for agent-centric joins.
- [ ] 12-02: Expose agent-centric receipt queries through the query API using the capability lineage index.
- [ ] 12-03: Build receipt dashboard SPA (React 18 / Vite 6 / TanStack Table 8 / Recharts 2) with filter, drill-down, delegation chain, and budget views.
- [ ] 12-04: Integrate dashboard SPA into axum server via tower_http::ServeDir; verify non-engineer stakeholder use case end to end.

## Progress

**Execution Order:**
v1.0 phases complete. v2.0 executes in numeric order: 7 -> 8 -> 9 -> 10 -> 11 -> 12

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. E9 HA Trust-Control Reliability | v1.0 | 4/4 | Complete | 2026-03-19 |
| 2. E12 Security Boundary Completion | v1.0 | 4/4 | Complete | 2026-03-19 |
| 3. E10 Remote Runtime Hardening | v1.0 | 4/4 | Complete | 2026-03-19 |
| 4. E11 Cross-Transport Concurrency Semantics | v1.0 | 4/4 | Complete | 2026-03-20 |
| 5. E13 Policy and Adoption Unification | v1.0 | 4/4 | Complete | 2026-03-19 |
| 6. E14 Hardening and Release Candidate | v1.0 | 4/4 | Complete | 2026-03-20 |
| 7. Schema Compatibility and Monetary Foundation | 2/2 | Complete   | 2026-03-22 | - |
| 8. Core Enforcement | 4/4 | Complete   | 2026-03-22 | - |
| 9. Compliance and DPoP | 2/3 | In Progress|  | - |
| 10. Receipt Query API and TypeScript SDK 1.0 | 3/3 | Complete    | 2026-03-23 | - |
| 11. SIEM Integration | 3/3 | Complete   | 2026-03-23 | - |
| 12. Capability Lineage Index and Receipt Dashboard | v2.0 | 0/4 | Not started | - |
