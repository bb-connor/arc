# Project Research Summary

**Project:** PACT v2.0 Agent Economy Foundation
**Domain:** Capability-based security protocol with economic primitives and compliance observability
**Researched:** 2026-03-21
**Confidence:** HIGH

## Executive Summary

PACT v2.0 is a security protocol milestone that transforms an existing capability-based access control system into a full agent economy infrastructure. The v1.0 foundation (Ed25519 signing, fail-closed guards, signed receipts, HA cluster replication) is solid and validated. The v2.0 work adds the economic and compliance layer on top: monetary budgets, tamper-evident Merkle receipt commitment, velocity controls, SIEM integration, and a receipt dashboard. The core challenge is not building new infrastructure from scratch but sequencing extensions to existing types correctly, porting and adapting ClawdStrike code without inheriting its domain-specific assumptions, and meeting two hard regulatory deadlines (Colorado AI Act June 30, 2026; EU AI Act August 2, 2026).

The recommended approach is a strict dependency-ordered build sequence. A schema compatibility release must ship first to remove `deny_unknown_fields` from 18 serialized types before any new fields appear on the wire -- this is a critical gate with no exceptions. The monetary budget and Merkle commitment work can proceed in parallel after that gate, followed by the velocity guard, receipt query API, and DPoP proof-of-possession. Q3 work (SIEM exporters, capability lineage index, receipt dashboard) depends on Q2 foundations being stable. The TypeScript SDK must reach 1.0 quality in parallel with the core protocol work to unblock the largest developer population.

The primary risks are sequencing failures (new fields shipping before schema migration lands, breaking old kernels), incorrect port decisions (using ClawdStrike's HTTP-shaped DPoP proof message instead of a PACT-native invocation proof), and compliance document timing (filing documents that describe planned features rather than shipped code). All three risks are preventable through explicit phase gates and per-phase verification criteria. The monetary budget HA consistency model also requires deliberate design documentation: the existing LWW replication strategy has a bounded overrun window under split-brain that must be explicitly acknowledged rather than silently inherited from the invocation-count model.

## Key Findings

### Recommended Stack

The existing Rust workspace stack (Rust 1.93 MSRV, tokio 1, axum 0.8, rusqlite 0.37 bundled, serde/serde_json 1, ed25519-dalek 2, uuid 1, chrono 0.4) requires minimal additions for v2.0. New dependencies are kept deliberately small: `lru 0.12` for DPoP nonce replay prevention in `pact-kernel`, and `reqwest 0.13` plus `tower 0.5` in a new `pact-siem` crate for SIEM HTTP fan-out. SQLite FTS5 for receipt full-text search is already enabled in the bundled rusqlite build. Monetary arithmetic uses plain `u64` micro-unit integers rather than a decimal library, eliminating floating-point precision risk with zero new dependencies.

The receipt dashboard is a static React 18 / Vite 6 / TypeScript 5 SPA served by the existing axum server via `tower_http::ServeDir`. TanStack Table 8 handles the receipt audit log; Recharts 2 handles time-series charts; TanStack Query 5 manages data fetching. This is the correct weight for an operator-facing compliance dashboard -- no SSR, no heavy component libraries, no Redux.

**Core technologies:**
- `u64` micro-unit integers: monetary amounts -- no rust_decimal needed, no floating-point risk
- `lru 0.12`: DPoP nonce replay store -- zero dependencies, O(1) eviction, MSRV-compatible
- `reqwest 0.13` (rustls-tls): SIEM HTTP client -- async fan-out, no OpenSSL, cross-compilation safe
- `tower 0.5`: SIEM retry/timeout middleware -- already transitive via axum, promotes to explicit dep
- React 18 + Vite 6 + TanStack Table 8: receipt dashboard -- static SPA, served via ServeDir
- SQLite FTS5: receipt full-text search -- already enabled in bundled rusqlite 0.37, no extra crate

### Expected Features

The v2.0 feature set is anchored to two hard regulatory deadlines and one adoption gate (TypeScript SDK 1.0). The competitive moat comes from features no other agent protocol provides at the authorization layer: monetary budget enforcement with delegation attenuation, per-invocation proof-of-possession, Merkle-committed signed receipts, and SIEM integration with cryptographically attested events.

**Must have (table stakes for v2.0 launch, Q2-Q3 2026):**
- `deny_unknown_fields` removal -- unblocks every other v2.0 feature; must ship first
- Merkle receipt commitment with signed checkpoints -- compliance tamper-evident claim must be backed by code before Colorado deadline
- Monetary budgets (single currency, `MonetaryAmount` with `u64` micro-units) -- makes PACT legible to CFOs
- Colorado AI Act compliance mapping (deadline June 30, 2026) -- deployment blocker for US regulated customers
- EU AI Act Article 19 compliance mapping (deadline August 2, 2026) -- deployment blocker for EU regulated customers
- Receipt query API with pagination -- write-only audit trail has no compliance value
- Receipt retention and rotation policy -- EU Article 19 requires configurable retention periods
- Velocity guard (invocation and spend windows) -- CFO-grade time-window spending governance
- Capability lineage index -- prerequisite for dashboard and agent-centric analytics
- Receipt dashboard (read-only, compliance officer UX) -- converts regulatory pressure into deployment decisions
- TypeScript SDK 1.0 -- adoption blocker for the largest developer population
- SIEM exporters (at least 2: Splunk + Elasticsearch) -- enterprise security teams require SIEM visibility

**Should have (differentiators, v2.x Q3-Q4 2026):**
- DPoP per-invocation proof-of-possession -- closes stolen-token replay story; defer if Q2 scope pressure mounts
- Financial receipt metadata (`FinancialReceiptMetadata`) -- billing ledger enrichment; triggers when monetary budgets reach production
- Python SDK 1.0 -- promotes after TS SDK proves the model; needed for LangGraph/CrewAI integrations
- Receipt analytics API (aggregations) -- triggers when design partners need aggregate views
- Payment rail bridge (Stripe or x402 adapter) -- Q4 2026, after monetary budgets prove stable

**Defer (v3+, Q1 2027 and beyond):**
- Agent reputation scoring -- requires capability lineage index plus sufficient receipt volume
- Multi-currency budgets with exchange-rate binding -- Q4 2026 at earliest; single-currency must prove first
- A2A trust adapter -- spec stability uncertain; defer until Google stabilizes v1.0
- Byzantine consensus / multi-region HA -- architecturally premature; position for Q3 2027+

### Architecture Approach

PACT v2.0 extends the existing 7-crate workspace without adding new top-level crates in Q2. New functionality lands as modules inside existing crates: `pact-core` gains monetary types, `pact-kernel` gains `checkpoint.rs`, `dpop.rs`, and `receipt_query.rs`, and `pact-guards` gains `velocity.rs`. A new `pact-siem` crate ships in Q3 behind a feature flag to isolate HTTP client dependencies from the TCB (Trusted Computing Base). The kernel's synchronous guard contract is a hard architectural constraint: all guards use `std::sync::Mutex`, not `tokio::Mutex`. SIEM export uses a cursor-based pull model against the receipt store so it never touches the kernel hot path. Monetary debits happen atomically before guard evaluation using SQLite `IMMEDIATE` transactions; the kernel fails closed if the debit fails.

**Major components and v2.0 changes:**
1. `pact-core` -- ADD `MonetaryAmount`, `ToolInvocationCost`, new `ToolGrant` fields; REMOVE `deny_unknown_fields`
2. `pact-kernel` -- ADD `checkpoint.rs` (Merkle batching), `dpop.rs` (proof validation), `receipt_query.rs`; EXTEND `budget_store.rs` with `try_charge_cost()`
3. `pact-guards` -- ADD `velocity.rs` (synchronous token-bucket, `std::sync::Mutex`)
4. `pact-siem` (new crate, Q3) -- ExporterManager cursor-pull, 6 exporters (Splunk, Elastic, Datadog, Sumo, Webhooks, Alerting), DLQ, per-exporter rate limit
5. `pact-kernel::capability_index` (Q3) -- snapshot persistence at issuance time; enables agent-centric joins
6. Receipt dashboard SPA (Q3) -- React/Vite, served via `tower_http::ServeDir`, reads receipt query API

### Critical Pitfalls

1. **`deny_unknown_fields` not removed before new fields ship** -- 18 types carry this attribute; old kernels will hard-reject tokens containing new fields (MonetaryAmount, DPoP binding, etc.). Prevention: ship the removal as a dedicated first release; verify with a cross-version round-trip test. Recovery cost if missed: HIGH (requires rolling back all new-field-bearing kernels and re-issuing all active capability tokens).

2. **DPoP proof message copied from ClawdStrike's HTTP shape** -- ClawdStrike binds proofs to `method + url + body_sha256`; PACT must bind to `capability_id + tool_server + tool_name + arg_hash + issued_at + nonce`. Copying the HTTP shape means proofs do not actually bind to specific PACT invocations. Prevention: rewrite `binding_proof_message()` explicitly; test that a proof for invocation A is rejected for invocation B. Recovery cost if missed: HIGH (requires rotating all active tokens and patching all clients).

3. **Velocity guard implemented with `tokio::Mutex` or `async fn`** -- `Guard::evaluate()` is a synchronous trait method; async implementation causes executor-within-executor panics. Prevention: use `std::sync::Mutex` with synchronous `try_acquire()` returning `Verdict::Deny` immediately; verify with a `#[test]` (non-async) harness.

4. **Merkle checkpoint computed per-receipt rather than batched** -- `MerkleTree::from_leaves` materializes all leaf hashes; per-receipt triggers create O(n) read cost at receipt volume. Prevention: checkpoint every N receipts (default 100); stage leaf hashes in memory; verify with a 1,000-receipt benchmark showing append latency does not regress beyond 2x baseline.

5. **Monetary budget HA overrun undocumented** -- LWW replication under split-brain allows both HA nodes to approve charges concurrently up to the per-invocation limit before reconciliation. Not necessarily wrong, but must be a deliberate documented decision. Prevention: explicitly document the overrun bound in the design; add a concurrent-charge HA test that names the exposure window in its assertion message.

6. **Compliance documents filed before features ship** -- Colorado deadline is June 30, 2026. Documents that describe Merkle commitment as tamper-evident before Merkle wiring passes acceptance tests create regulatory exposure. Prevention: gate compliance document review on feature acceptance tests; maintain a traceability matrix linking each claim to a passing test artifact.

## Implications for Roadmap

Based on the dependency graph in ARCHITECTURE.md and the regulatory deadlines in FEATURES.md, the research points clearly to a 4-phase structure for v2.0 with two Q3 follow-on phases.

### Phase 1: Schema Compatibility and Monetary Foundation

**Rationale:** `deny_unknown_fields` removal is a hard prerequisite for every other v2.0 feature. Nothing with new wire fields can ship until this gate is closed. Monetary types (`MonetaryAmount`, `ToolInvocationCost`) and the `ToolGrant` cost fields must ship in the same release to establish the economic primitive before the Colorado deadline. This phase establishes the foundation without yet wiring enforcement.

**Delivers:** Forward-compatible serialized types; `MonetaryAmount` and `ToolInvocationCost` types in `pact-core`; new optional fields on `ToolGrant`; migration test for pre-existing databases.

**Addresses:** `deny_unknown_fields` removal (table stakes P1), monetary budget types (table stakes P1), schema forward-compatibility (table stakes P1)

**Avoids:** Pitfall 1 (deny_unknown_fields sequencing), Pitfall 7 (SQLite migration without pre-migration test)

**Research flag:** Standard patterns -- well-defined in ARCHITECTURE.md with explicit code examples. Skip phase research.

### Phase 2: Core Enforcement (Parallel Track)

**Rationale:** After Phase 1 lands, three enforcement features can be built in parallel since they share no runtime dependencies on each other: monetary debit (`try_charge_cost` in `pact-kernel`), Merkle checkpoint batching, and velocity guard. Wiring all three into the kernel execution path comes after the individual modules are validated. This phase also delivers the receipt query API and the `pact receipt list` CLI subcommand, which are needed before the Colorado deadline to make receipts queryable.

**Delivers:** `try_charge_cost()` with SQLite IMMEDIATE transactions; `checkpoint.rs` with batch-N Merkle signing; `VelocityGuard` with synchronous token-bucket; `ReceiptQuery` API with pagination; `pact receipt list` CLI subcommand.

**Addresses:** Monetary budget enforcement (P1), velocity guard (P1), Merkle commitment (P1), receipt query API (P1)

**Avoids:** Pitfall 3 (async velocity guard), Pitfall 4 (monetary HA overrun undocumented), Pitfall 5 (per-receipt Merkle checkpoint), Pitfall 6 (ClawdStrike tenant model in receipt query)

**Research flag:** Merkle checkpoint batching follows Certificate Transparency log patterns (well-documented). Velocity guard is a direct port. Skip phase research.

### Phase 3: Compliance and Observability

**Rationale:** With core enforcement in place and verified, the compliance artifacts can be written against shipping code. Receipt retention and rotation must be implemented before the EU Article 19 compliance document can make accurate claims about configurable retention periods. DPoP can ship in this phase (P2 priority) or be deferred if Phase 2 overruns; the verification gate is strict (cross-invocation replay test).

**Delivers:** Colorado AI Act compliance mapping (filed before June 30, 2026); EU AI Act Article 19 compliance mapping (filed before August 2, 2026); receipt retention/rotation with configurable policy; DPoP proof-of-possession (kernel verifier + bindings-core proof generation helpers).

**Addresses:** Colorado compliance (P1, hard deadline), EU compliance (P1, hard deadline), receipt retention (P1), DPoP (P2)

**Avoids:** Pitfall 2 (HTTP-shaped DPoP proof message), Pitfall 9 (compliance documents that lead code)

**Research flag:** Compliance document content (Colorado SB 24-205 and EU AI Act Article 19 specifics) may benefit from targeted legal/regulatory research during planning. Flag for phase research.

### Phase 4: TypeScript SDK 1.0

**Rationale:** The TS SDK is the primary adoption gate for the largest developer population. It must reach 1.0 quality before enterprise design partners can integrate. This phase runs in parallel with Phases 2-3 where possible but must be complete before v2.0 launch. DPoP SDK helpers (proof generation in bindings-core) depend on the DPoP kernel verifier from Phase 3.

**Delivers:** TypeScript SDK at stable 1.0, npm-published, with stable error handling, retry semantics, and DPoP proof generation helpers.

**Addresses:** TypeScript SDK 1.0 (P1, adoption blocker)

**Research flag:** SDK API design patterns for capability-based protocols are niche. Flag for phase research.

### Phase 5: SIEM Integration (Q3)

**Rationale:** SIEM exporters depend on the receipt query API (Phase 2) and pull from the SQLite store via cursor. The `pact-siem` crate must be feature-flagged to keep pact-kernel's TCB lean. This phase delivers enterprise security stack integration and is a P2 priority requiring at least 2 exporters (Splunk + Elasticsearch) at launch.

**Delivers:** `pact-siem` crate with ExporterManager, DLQ with size cap, 6 exporters (Splunk, Elastic, Datadog, Sumo Logic, Webhooks, Alerting), ECS/CEF/OCSF/Native schema formats.

**Addresses:** SIEM exporters (P2), FinancialReceiptMetadata enrichment (P2)

**Avoids:** Pitfall 8 (SIEM DLQ unbounded growth), anti-pattern 1 (HTTP deps in pact-kernel)

**Research flag:** SIEM target APIs (Splunk HEC, Elasticsearch bulk, Datadog) have well-documented integration patterns. Skip phase research.

### Phase 6: Capability Lineage Index and Receipt Dashboard (Q3)

**Rationale:** The capability lineage index must ship before the dashboard is built (not in parallel) to avoid dashboard data model workarounds that fight the later index. Build the index as a stub first so the dashboard degrades gracefully, then fill it in. This phase delivers the primary compliance officer UX.

**Delivers:** `capability_index.rs` with snapshot persistence; agent-centric receipt queries via subject_key index; React/Vite receipt dashboard SPA with filter/drill-down/budget views; served statically via axum `ServeDir`.

**Addresses:** Capability lineage index (P1), receipt dashboard (P1), receipt analytics API (P2)

**Avoids:** Pitfall 10 (lineage index assumed before built), anti-pattern 4 (premature agent-centric joins)

**Research flag:** Dashboard component patterns (TanStack Table + Recharts integration) are well-documented. Skip phase research.

### Phase Ordering Rationale

- **Schema migration must precede all wire-format changes** -- this is not a soft dependency; it is a hard wire compatibility gate. Any plan that sequences new fields before the migration is incorrect.
- **Enforcement before compliance documentation** -- the Colorado and EU AI Act compliance artifacts must describe working, tested code. The compliance phase (Phase 3) is gated on Phase 2 acceptance tests passing.
- **Lineage index before dashboard** -- building the dashboard against a stub API (empty index) is explicitly called out in PITFALLS.md as the correct approach; building against workaround joins is the anti-pattern to avoid.
- **SIEM isolation** -- pact-siem ships as a feature-flagged crate to protect pact-kernel's TCB audit surface. This is a hard architectural boundary, not an optimization.
- **TS SDK parallel track** -- SDK work does not block core protocol work but must complete before v2.0 launch; DPoP helpers depend on Phase 3 kernel verifier.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 3 (Compliance):** Colorado SB 24-205 and EU AI Act Article 19 specific requirements, recordkeeping formats, and filing procedures are regulatory/legal domain knowledge that may need targeted research to write accurate compliance documentation.
- **Phase 4 (TypeScript SDK 1.0):** SDK API design for capability-based protocols is a niche area; the right shape for DPoP proof generation helpers in TypeScript warrants research to get the developer ergonomics correct.

Phases with standard patterns (skip research-phase):
- **Phase 1 (Schema):** The serde migration pattern is explicitly documented in ARCHITECTURE.md with code examples. Straightforward to implement.
- **Phase 2 (Enforcement):** Token-bucket velocity guard, SQLite atomic transactions, and Merkle batch checkpointing all follow well-established patterns documented in the codebase and integration plan.
- **Phase 5 (SIEM):** All 6 SIEM target APIs have stable, well-documented integration endpoints. The exporter structure is a direct port from ClawdStrike with documented adaptations.
- **Phase 6 (Dashboard):** React + TanStack Table + Recharts is a standard combination with extensive documentation.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All crate selections verified via crates.io/docs.rs. Existing stack is battle-tested in v1.0. New deps are minimal and well-chosen. One LOW-confidence item: tower 0.5 retry layer usage for SIEM needs integration testing. |
| Features | HIGH | Driven by first-party strategic documents, codebase analysis, and regulatory text. Hard deadlines are confirmed (Colorado June 30, EU August 2). Competitor landscape is well-researched. |
| Architecture | HIGH | Based on direct codebase analysis, not external sources. Component boundaries, data flow, and build order are derived from actual crate structure and existing patterns. |
| Pitfalls | HIGH | All 10 pitfalls derived from actual codebase (confirmed deny_unknown_fields count: 18 types), existing risk register (CLAWDSTRIKE_INTEGRATION.md Section 8), and structural analysis of port decisions. |

**Overall confidence:** HIGH

### Gaps to Address

- **Tower 0.5 retry layer for SIEM:** The retry/timeout middleware pattern for reqwest + tower in pact-siem is conceptually sound but has not been tested against actual SIEM endpoints. Validate the ServiceBuilder retry pattern in a spike before committing to it in Phase 5.
- **Dashboard embedding strategy:** The exact approach for embedding the Vite SPA dist directory in the axum binary (especially for air-gapped or Docker deployments) has MEDIUM confidence. The `include_dir!` macro approach for embedded deployments vs. `ServeDir` for standard deployments needs a concrete decision before Phase 6 planning.
- **Monetary HA overrun bound:** The acceptable overrun window under split-brain is a product decision, not a technical one. Research can document the pattern but the bound (`max_cost_per_invocation x node_count`) must be agreed by product and documented in the capability spec before Phase 2 ships.
- **Colorado SB 24-205 specifics:** The compliance research confirms the deadline and general requirement (records of AI system outputs and basis for outputs) but the exact filing format and recordkeeping specifications need regulatory review before Phase 3 drafts the document.

## Sources

### Primary (HIGH confidence)
- `docs/CLAWDSTRIKE_INTEGRATION.md` -- port plan, type mappings, risk register (Sections 3.1, 3.2, 3.3, 3.5, 8)
- `docs/AGENT_ECONOMY.md` -- monetary budget design, velocity controls, receipt metadata, payment rail abstraction
- `docs/STRATEGIC_ROADMAP.md` -- Q2/Q3 deliverables, debate resolution sequencing, regulatory deadlines
- `crates/pact-core/src/capability.rs` -- 18 `deny_unknown_fields` annotations confirmed by direct inspection
- `crates/pact-core/src/receipt.rs` -- receipt type structures confirmed
- `crates/pact-kernel/src/lib.rs` -- synchronous `Guard::evaluate()` trait confirmed
- `crates/pact-core/src/merkle.rs` -- `MerkleTree::from_leaves` semantics confirmed
- `.planning/PROJECT.md` -- v2.0 milestone scope, constraints, regulatory deadlines
- `rusqlite 0.37` releases (GitHub) -- FTS5 enabled in bundled build with SQLite 3.50.2
- `reqwest 0.13.2` (docs.rs) -- current stable, rustls-tls default
- `lru 0.12` (crates.io) -- zero-dep, MSRV 1.65+, actively maintained

### Secondary (MEDIUM confidence)
- `docs/COMPETITIVE_LANDSCAPE.md` -- A2A, MCP, Stripe ACP, x402, UCAN, AIUC, SPIFFE comparison
- `docs/research/AGENT_ECONOMY_RESEARCH.md` -- market data, regulatory research, attestation precedents
- `tower 0.5` + `reqwest 0.13` retry pattern -- conceptually sound; integration testing needed
- Receipt dashboard embedding strategy -- ServeDir approach verified in pattern docs; air-gapped strategy needs spike

### Tertiary (LOW confidence)
- `ocsf-schema-rs` (crates.io) -- maturity unverified; inline struct approach preferred and documented
- `rust-cef` (crates.io) -- maintenance uncertain; inline CEF serializer (50 lines) recommended instead
- Colorado SB 24-205 filing specifics -- deadline and general requirement confirmed; exact recordkeeping format needs regulatory review

---
*Research completed: 2026-03-21*
*Ready for roadmap: yes*
