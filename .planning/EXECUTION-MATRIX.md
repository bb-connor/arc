# ARC Roadmap Execution Matrix

> **Generated**: 2026-04-16
> **Last Updated**: 2026-04-16 15:50 UTC (post Wave 1 commit)
> **Methodology**: Cross-referenced roadmap stories against actual codebase (crates/, sdks/, docs/) with git commit history verification
> **Known completed**:
>  - Wave 0: 0.3 (788f69c), 1.2 (27488eb), 2.1 (f5a8a58), 15.2-15.5 (98252dd), 16.1 (f7c738f)
>  - Wave 1a: 0.5 (224a05c), 1.3 (3e258a3), 1.4 (225193d), 7.1 (b3666a9)
>  - Wave 1b: 2.2 (f6a8820), 9.1 (7f4d0d7), 12.2 (dec8378), 16.2 (8234a4d)

---

## Phase 0: Developer Experience Foundation

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 0.1 | Publish Python SDKs to PyPI | PARTIAL | `sdks/python/arc-sdk-python/pyproject.toml` exists with metadata; no CI publish workflow found (`.github/workflows/publish-python.yml` missing) | CI/CD pipeline for automatic PyPI publishing on git tag |
| 0.2 | Publish TypeScript SDKs to npm | PARTIAL | `sdks/typescript/packages/{elysia,express,fastify,node-http}/package.json` exist with npm metadata; `.github/workflows/publish-typescript.yml` missing | CI/CD pipeline for npm registry publishing |
| 0.3 | MockArcClient for Testing | SHIPPED | Commit 788f69c: `sdks/python/arc-sdk-python/src/arc_sdk/testing.py` with `MockArcClient`, `allow_all()`, `deny_all()`, `with_policy()` factories; `tests/test_mock_client.py` ✓ | — |
| 0.4 | Pre-Built Binary Distribution | MISSING | No `.github/workflows/release-binaries.yml`; no `Dockerfile.sidecar`; no Homebrew tap | Cross-platform binary builds, Homebrew formula, Docker image |
| 0.5 | Error Message Improvements | SHIPPED | Commit 224a05c: enriched Deny verdict with structured context (scope, guard evidence, next-steps) | — |

---

## Phase 1: Structural Security Fixes

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 1.1 | Execution Nonces (TOCTOU Fix) | MISSING | No `arc-kernel/src/execution_nonce.rs` found; no grep matches for `ExecutionNonce` type | Implement nonce generation, validation, and store trait |
| 1.2 | Trust Level Taxonomy | SHIPPED | Commit 27488eb: `crates/arc-core-types/src/receipt.rs` contains `pub enum TrustLevel { Mediated, Verified, Advisory }` with field on `ArcReceipt` and `ChildRequestReceiptBody` ✓ | — |
| 1.3 | WASM Guard Module Signing | SHIPPED | Commit 3e258a3: Ed25519 signing for WASM guard modules at load | — |
| 1.4 | Emergency Kill Switch | SHIPPED | Commit 225193d: emergency_stop/resume on kernel + HTTP endpoints | — |
| 1.5 | Multi-Tenant Receipt Isolation | MISSING | `tenant_id` appears only in test config (federated_issue.rs, provider_admin.rs); NOT on `ArcReceipt` or `receipt_store` (5 test-only matches in arc-cli) | Add tenant_id field to receipt, modify receipt store SQL, enforce WHERE clause |

---

## Phase 2: Core Type Evolution

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 2.1 | New ToolAction Variants | SHIPPED | Commit f5a8a58: `crates/arc-guards/src/action.rs` contains `ToolAction::CodeExecution { language, code }`, `BrowserAction { verb, target }`, `DatabaseQuery { database, query }`, `ExternalApiCall { service, endpoint }`, `MemoryWrite { store, key }`, `MemoryRead { store, key }`; extraction heuristics in `extract_action()` ✓ | — |
| 2.2 | New Constraint Variants | SHIPPED | Commit f6a8820: 11 new Constraint variants (TableAllowlist, ColumnDenylist, MaxRowsReturned, OperationClass, AudienceAllowlist, ContentReviewTier, MaxTransactionAmountUsd, RequireDualApproval, ModelConstraint, MemoryStoreAllowlist, MemoryWriteDenyPatterns) + kernel request_matching enforcement for Audience/Memory variants | — |
| 2.3 | ModelConstraint Implementation | MISSING | No `ModelMetadata`, `ModelSafetyTier`, or `ModelConstraint` types found in arc-core-types; no kernel evaluation logic | Define types, add constraint evaluator in kernel, test against model_metadata |
| 2.4 | Plan-Level Evaluation | MISSING | No `PlannedToolCall`, `PlanEvaluationRequest`, `PlanEvaluationResponse` types; no `evaluate_plan()` kernel method; no `/evaluate-plan` endpoint | Plan types in arc-core-types, kernel method, HTTP route, verdict per step |

---

## Phase 3: Content Safety and Human-in-the-Loop

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 3.1 | PromptInjectionGuard | MISSING | No `arc-guards/src/prompt_injection.rs` or `text_utils.rs` found; 0 grep matches for PromptInjectionGuard | Port from ClawdStrike, 6-signal detector, canonicalization, fingerprint dedup |
| 3.2 | JailbreakGuard | MISSING | No `arc-guards/src/jailbreak.rs` or `jailbreak_detector.rs` | 4-layer detector (heuristic, statistical, ML, LLM), scoring layer |
| 3.3 | Output Sanitizer Completion | PARTIAL | `crates/arc-guards/src/response_sanitization.rs` exists; `post_invocation.rs` exists; no evidence of secret detection, Luhn validation, entropy scanning, allowlist/denylist overlap resolution | Extend response_sanitization with full PII/secret/entropy detection pipeline |
| 3.4 | HITL: Kernel Verdict Extension | MISSING | No `Verdict::PendingApproval` variant; no `arc-kernel/src/approval.rs`; no approval guard, store, HTTP routes | PendingApproval verdict variant, ApprovalGuard, approval store, resume flow, webhook firing |
| 3.5 | HITL Persistence Backend | MISSING | No `arc-store-sqlite/src/approval_store.rs` or `batch_approval_store.rs`; no approval store traits | SQLite backend for approval persistence, kernel reload on restart |
| 3.6 | Approval Channels | MISSING | No `arc-kernel/src/approval_channels.rs`; no `ApprovalChannel` trait or webhook implementation | Webhook, Slack, dashboard channels; trait abstraction |

---

## Phase 4: Flagship Integration – arc-code-agent

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 4.1 | arc-code-agent Python Package | MISSING | No `sdks/python/arc-code-agent/` directory | Package scaffold, CodeAgent wrapper, default policy, tests |
| 4.2 | MCP Sidecar Wrapper for Coding Agents | MISSING | No `arc mcp serve --preset code-agent`; no `crates/arc-cli/src/policies/code_agent.yaml` | CLI preset, bundled policy, MCP server wrapping |
| 4.3 | Migration Guide: MCP to ARC | MISSING | No `docs/guides/MIGRATING-FROM-MCP.md` | Step-by-step integration guide |

---

## Phase 5: ClawdStrike Guard Absorption (Remaining)

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 5.1 | ComputerUseGuard | MISSING | No `arc-guards/src/computer_use.rs` | Action-type allowlisting, Observe/Guardrail/FailClosed modes |
| 5.2 | InputInjectionCapabilityGuard | MISSING | No `arc-guards/src/input_injection.rs` | Input-type restrictions, postcondition probe validation |
| 5.3 | RemoteDesktopSideChannelGuard | MISSING | No `arc-guards/src/remote_desktop.rs` | Per-channel enable/disable, transfer size limits |
| 5.4 | SpiderSense Embedding Detector | MISSING | No `arc-guards/src/spider_sense.rs`; no `data/spider_sense_patterns.json` | Cosine similarity detector, pattern database |
| 5.5 | Policy Engine: Guard Compilation | PARTIAL | `crates/arc-policy/src/` exists (11 files); no evidence of extended compiler covering all 12 guard types or 7 ported rulesets | Complete guard type compilation, port 7 built-in rulesets |
| 5.6 | Custom Guard Registry: WASM Merge | MISSING | No `load_guards_from_policy()` in arc-wasm-guards; no `placeholders.rs` with env var resolution | Policy-driven WASM guard loading, placeholder resolution, capability intersection |

---

## Phase 6: Agent Framework SDKs

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 6.1 | arc-crewai | MISSING | No `sdks/python/arc-crewai/` directory | BaseTool wrapper, per-role scoping, delegation, PyPI publish |
| 6.2 | arc-autogen | MISSING | No `sdks/python/arc-autogen/` directory | Function registration wrapper, group chat governance |
| 6.3 | arc-llamaindex | MISSING | No `sdks/python/arc-llamaindex/` directory | FunctionTool wrapper, RAG pipeline scoping |
| 6.4 | @arc-protocol/ai-sdk | MISSING | No `sdks/typescript/packages/ai-sdk/` directory | Vercel AI SDK wrapper, streaming support |

---

## Phase 7: Data Layer Guards

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 7.1 | SqlQueryGuard | SHIPPED | Commit b3666a9: arc-data-guards crate with SqlQueryGuard | — |
| 7.2 | VectorDbGuard | MISSING | No `vector_guard.rs` in arc-data-guards | Collection scoping, operation class, top_k limits |
| 7.3 | WarehouseCostGuard | MISSING | No `warehouse_cost_guard.rs`; no `CostDimension::WarehouseQuery` in arc-metering | Pre-execution cost estimation, MaxBytesScanned/MaxCostPerQuery |
| 7.4 | QueryResultGuard (Post-Invocation) | MISSING | No `result_guard.rs` | Row count enforcement, column redaction, PII pattern matching |

---

## Phase 8: Code Execution Guards

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 8.1 | CodeExecutionGuard | MISSING | No `arc-guards/src/code_execution.rs` | Language allowlist, network control, timeout, dangerous module detection |
| 8.2 | BrowserAutomationGuard | MISSING | No `arc-guards/src/browser_automation.rs` | Domain allowlists, action restrictions, credential detection |

---

## Phase 9: Networking – Envoy ext_authz

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 9.1 | gRPC ext_authz Adapter | SHIPPED | Commit 7f4d0d7: arc-envoy-ext-authz crate with EnvoyKernel trait, Check RPC, vendored envoy v3 protos | — |
| 9.2 | Istio Integration Example | MISSING | No `examples/istio-ext-authz/` | Reference AuthorizationPolicy, K8s manifests |

---

## Phase 10: Orchestration Integrations

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 10.1 | arc-temporal (Python) | MISSING | No `sdks/python/arc-temporal/` | ArcActivityInterceptor, WorkflowGrant, receipt aggregation |
| 10.2 | arc-lambda-extension | MISSING | No `sdks/lambda/` directory | Lambda Extension binary, pre-built Layer |
| 10.3 | arc-langgraph | MISSING | No `sdks/python/arc-langgraph/` | arc_node wrapper, approval node, depends on Phase 3 HITL |

---

## Phase 11: SaaS, Communication, and Streaming

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 11.1 | Content-Review Guard | MISSING | No `arc-guards/src/content_review.rs` | Pre-invocation PII/tone/profanity, per-service config |
| 11.2 | arc-streaming (Kafka) | MISSING | No `sdks/python/arc-streaming/` | ArcConsumerMiddleware, DLQ governance, transactional commit |
| 11.3 | IaC Governance (arc-iac) | MISSING | No `sdks/python/arc-iac/` | Terraform CLI wrapper, Pulumi decorators |

---

## Phase 12: SIEM and Observability Completion

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 12.1 | Missing SIEM Exporters | PARTIAL | `crates/arc-siem/src/exporters/` exists with some exporters; no Datadog, Sumo Logic, webhook, or alerting exporters found | Port 4 missing exporters from ClawdStrike |
| 12.2 | OCSF Receipt Format | SHIPPED | Commit dec8378: arc-siem/src/ocsf.rs with OCSF 3002 mapping + OcsfExporter backend | — |
| 12.3 | LangSmith / LangFuse Bridge | MISSING | No `sdks/python/arc-observability/` | Receipts as enriched spans in observability platforms |

---

## Phase 13: Async Guard Runtime and Threat Intelligence

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 13.1 | AsyncGuardAdapter Infrastructure | MISSING | No `arc-guards/src/external/` with circuit breaker, cache, retry modules | ExternalGuard trait, AsyncGuardAdapter, circuit breaker pattern |
| 13.2 | Cloud Guardrail Adapters | MISSING | No Bedrock, Azure, or Vertex safety adapters | 3 cloud guardrail implementations |
| 13.3 | Threat Intelligence Guards | MISSING | No `threat_intel/` directory with VirusTotal, Safe Browsing, Snyk | 3 threat intel ExternalGuard impls |

---

## Phase 14: Portable Kernel (WASM)

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 14.1 | arc-kernel-core Extraction | MISSING | No `crates/arc-kernel-core/` directory; no no_std+alloc kernel | Extract portable kernel subset, WASM compilation |
| 14.2 | Browser Bindings | MISSING | No `arc-kernel-browser` crate | wasm-bindgen bindings, Web Crypto support |
| 14.3 | Mobile FFI (iOS/Android) | MISSING | No `arc-kernel-mobile` crate | UniFFI bindings for Swift/Kotlin |

---

## Phase 15: Compliance

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 15.1 | FIPS Crypto Path | MISSING | `crates/arc-core-types/src/crypto.rs` uses Ed25519 (ed25519-dalek); no `SigningBackend` trait, no `aws-lc-rs` support, no P-256/P-384 option | FIPS trait abstraction, P-256/P-384 backend, algorithm identifier in serialization |
| 15.2 | NIST AI RMF Mapping | SHIPPED | Commit 98252dd: `docs/compliance/nist-ai-rmf.md` created with Govern/Map/Measure/Manage function mapping ✓ | — |
| 15.3 | PCI DSS v4.0 Mapping | SHIPPED | Commit 98252dd: `docs/compliance/pci-dss-v4.md` created with 12 requirement groups mapped ✓ | — |
| 15.4 | ISO 42001 Mapping | SHIPPED | Commit 98252dd: `docs/compliance/iso-42001.md` created with clause-level mapping ✓ | — |
| 15.5 | OWASP LLM Top 10 Coverage Matrix | SHIPPED | Commit 98252dd: `docs/compliance/owasp-llm-top-10.md` created with risk-to-control mapping ✓ | — |

---

## Phase 16: Economic Layer Developer Guide and Budget Hierarchy

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 16.1 | Economic Layer Developer Guide | SHIPPED | Commit f7c738f: docs/guides/ECONOMIC-LAYER.md | — |
| 16.2 | Hierarchical Budget Governance | SHIPPED | Commit 8234a4d: arc_metering::budget_hierarchy BudgetTree with org/dept/team/agent rollups; stateless policy with caller-supplied SpendSnapshot | — |

---

## Phase 17: Remaining Orchestration and Pipeline Integrations

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 17.1 | arc-prefect | MISSING | No `sdks/python/arc-prefect/` | @arc_task/@arc_flow decorators, Prefect Events |
| 17.2 | arc-dagster | MISSING | No `sdks/python/arc-dagster/` | @arc_asset decorator, partition-scoped capabilities |
| 17.3 | arc-airflow | MISSING | No `sdks/python/arc-airflow/` | ArcOperator wrapper, @arc_task decorator |
| 17.4 | arc-ray | MISSING | No `sdks/python/arc-ray/` | @arc_remote decorator, ArcActor base class |
| 17.5 | K8s Job Controller Extension | MISSING | No `sdks/k8s/controller/` | Job lifecycle capability grants |
| 17.6 | Cloud Run / ECS Sidecar Reference | MISSING | No `deploy/` directory with Cloud Run, ECS, Azure configs | Reference deployment manifests |

---

## Phase 18: Agent Memory Governance

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 18.1 | Memory Write/Read Guards | MISSING | No `arc-guards/src/memory_governance.rs` | Guards for MemoryWrite/MemoryRead ToolActions |
| 18.2 | Memory Entry Provenance | MISSING | No `arc-kernel/src/memory_provenance.rs` | Hash chain linking writes to capability IDs |

---

## Phase 19: Future Moats (Near-Term)

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 19.1 | Receipt Compliance Scoring | MISSING | No `arc-kernel/src/compliance_score.rs`; no `/compliance/score` endpoint; 0 grep matches for compliance_score | Scoring model (0-1000), CLI/HTTP surface |
| 19.2 | Agent Behavioral Profiling | PARTIAL | `crates/arc-guards/src/behavioral_sequence.rs` exists (baseline behavioral guard); no `behavioral_profile.rs` with anomaly detection and EMA | Extend BehavioralFeedReport with EMA/z-score anomaly guard |
| 19.3 | Regulatory API | MISSING | No `arc-http-core/src/regulatory_api.rs`; no `/regulatory/receipts` endpoint | Read-only API with SignedExportEnvelope wrapping |

---

## Phase 20: Future Moats (Medium-Term)

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 20.1 | Agent Passport: Trust-Tier Synthesis and WASM | PARTIAL | `crates/arc-credentials/src/passport.rs` exists with core passport system; no `trust_tier.rs` with compliance score synthesis; no `arc-kernel-core/src/passport_verify.rs` (blocked on 14.1) | trust_tier field synthesis from compliance+behavioral; WASM verification (blocked on Phase 14) |
| 20.2 | Agent Insurance Protocol | MISSING | No `arc-underwriting/src/premium.rs`; no `arc-market/src/insurance_flow.rs` | Premium pricing from receipt score, end-to-end claims flow |
| 20.3 | Cross-Kernel Federation: Bilateral Co-Signing | MISSING | `crates/arc-federation/src/` exists (core federation shipped); no `bilateral.rs` or `trust_establishment.rs` | bilateral receipt co-signing, mTLS key exchange between kernels |
| 20.4 | Capability Marketplace | PARTIAL | `crates/arc-listing/src/` and `arc-open-market/src/` exist; no `bidding.rs` with bid/ask protocol | Extend discovery/comparison, add bidding protocol |

---

## Execution Status Summary

### By Status (post Wave 1b, 2026-04-16 15:50 UTC)
- **SHIPPED**: 17 stories (0.3, 0.5, 1.2, 1.3, 1.4, 2.1, 2.2, 7.1, 9.1, 12.2, 15.2, 15.3, 15.4, 15.5, 16.1, 16.2 + 1 external program docs set)
- **PARTIAL**: 6 stories (0.1, 0.2, 3.3, 5.5, 12.1, 19.2, 20.1, 20.4)
- **MISSING**: 52 stories
- **BLOCKED**: 0 stories (no hard external blockers identified; Phase 3/14 dependencies documented)

### By Phase
| Phase | Total Stories | SHIPPED | PARTIAL | MISSING | BLOCKED |
|-------|---------------|---------|---------|---------|---------|
| 0 | 5 | 1 | 3 | 1 | — |
| 1 | 5 | 1 | — | 4 | — |
| 2 | 4 | 1 | 1 | 2 | — |
| 3 | 6 | — | 1 | 5 | — |
| 4 | 3 | — | — | 3 | — |
| 5 | 6 | — | 1 | 5 | — |
| 6 | 4 | — | — | 4 | — |
| 7 | 4 | — | — | 4 | — |
| 8 | 2 | — | — | 2 | — |
| 9 | 2 | — | — | 2 | — |
| 10 | 3 | — | — | 3 | — |
| 11 | 3 | — | — | 3 | — |
| 12 | 3 | — | 1 | 2 | — |
| 13 | 3 | — | — | 3 | — |
| 14 | 3 | — | — | 3 | — |
| 15 | 5 | 4 | — | 1 | — |
| 16 | 2 | — | — | 2 | — |
| 17 | 6 | — | — | 6 | — |
| 18 | 2 | — | — | 2 | — |
| 19 | 3 | — | 1 | 2 | — |
| 20 | 4 | — | 2 | 2 | — |

---

## Next Candidates: Wave 2 (post-1b)

**Criteria**: Disjoint write sets, no contention on hot files. Phase 2.2 Constraint variants are now shipped, so all data-layer / memory / financial guards downstream are unblocked.

### Wave 2: Zero-Contention, Ready Now
*These can start immediately on parallel branches. No hot-file contention.*

1. **7.2 VectorDbGuard** — `crates/arc-data-guards/src/vector_guard.rs` (new). Depends on shipped 7.1 (re-uses crate scaffolding). No kernel/core-types contention.
2. **7.3 WarehouseCostGuard** — `crates/arc-data-guards/src/warehouse_cost_guard.rs` (new) + optional `CostDimension::WarehouseQuery` in arc-metering/cost.rs. Self-contained.
3. **7.4 QueryResultGuard (post-invocation)** — `crates/arc-data-guards/src/result_guard.rs` (new). Consumes shipped MaxRowsReturned / ColumnDenylist constraints.
4. **12.1 Missing SIEM Exporters** — `crates/arc-siem/src/exporters/{datadog.rs,sumo_logic.rs,webhook.rs,alerting.rs}` (new). Sibling modules; mod.rs write is the only contention.
5. **0.4 Pre-Built Binary Distribution** — `.github/workflows/release-binaries.yml`, `Dockerfile.sidecar`, Homebrew formula. Pure CI/infra.
6. **17.6 Cloud Run / ECS Sidecar Reference** — `deploy/{cloud-run,ecs,azure}/*`. Pure manifest/config.
7. **3.1 PromptInjectionGuard** — `crates/arc-guards/src/prompt_injection.rs` (new). Self-contained content guard; pre-invocation only.
8. **5.6 Custom Guard Registry: WASM Merge** — `crates/arc-wasm-guards/src/placeholders.rs` (new) + `load_guards_from_policy()`. Depends on shipped 1.3 signing and shipped 2.2 constraints.

### Wave 3: Moderate Contention, Sequence After Wave 2
*Kernel or core-types writes; do after the above land.*

9. **2.3 ModelConstraint Implementation** — deepen `arc-kernel/src/kernel/mod.rs` evaluation for already-shipped ModelConstraint variant. Kernel contention.
10. **2.4 Plan-Level Evaluation** — new `arc-core-types::PlannedToolCall`, kernel `evaluate_plan()`, HTTP route. Large kernel + core-types write.
11. **15.1 FIPS Crypto Path** — `SigningBackend` trait in arc-core-types/src/crypto.rs; P-256/P-384 backend. Moderate contention.
12. **3.4 HITL Verdict + 3.5 Persistence + 3.6 Channels** — cluster; all three share `Verdict::PendingApproval` and ApprovalGuard. Serialize within cluster, parallelize across other waves.

---

## Dependency Chain for Accelerated Path

```
START (Wave 0: No deps)
├─ 0.4 (Binary Distribution)
├─ 1.3 (WASM Signing) ──→ 5.5 (Policy Engine) ──→ 5.6 (WASM Merge)
├─ 7.1 (SqlQueryGuard) ──→ 7.2, 7.3, 7.4 (Data Layer Complete)
├─ 16.1 (Economic Guide) ──→ 16.2 (Budget Hierarchy)
└─ 17.6 (Cloud Sidecar Patterns)

PHASE 2 (Core Types, ~1-2 weeks)
├─ 2.2 (Constraint Variants) ──→ 2.3 (ModelConstraint) ──→ 2.4 (Plan Eval)
└─ 2.3 ──→ 3.* (Content Safety)
    └─ 3.4/3.5/3.6 (HITL) ──→ 10.3 (arc-langgraph)

PHASE 3+ (Requires 2.*)
├─ 3.1, 3.2 (Guards) ──→ 3.3 (Sanitizer) ──→ content plane
├─ 5.* (Guard Absorption, depends on 2.1 ToolAction)
├─ 6.* (Framework SDKs, depends on Phase 0 publishing + 2)
├─ 7.* (Data Guards, depends on 2 Constraints + 2.1 ToolAction)
└─ 8.* (Code Exec Guards, depends on 2.1 ToolAction)

PHASE 4 (Flagship SDK, depends on Phase 0 publishing)
└─ 4.1, 4.2, 4.3 (arc-code-agent ecosystem)

PHASE 9 (Envoy, no deps) ──→ standalone

PHASE 14 (WASM Kernel, depends on 1,2,3)
└─ 14.1 (arc-kernel-core) ──→ 14.2 (Browser), 14.3 (Mobile)
    └─ 20.1 (Agent Passport, depends on 14.1 + 19.1/19.2)
```

---

## Hot File Serialization Risk Matrix

**High contention** (serialize work):
1. `arc-kernel/src/kernel/mod.rs` — touched by 1.1, 1.2, 1.4, 1.5, 2.2, 2.3, 2.4, 3.4, 3.5, 8.1, 8.2, 14.1, 18.2, 20.1, 20.3
2. `arc-core-types/src/capability.rs` — touched by 1.2, 2.2, 2.3, 15.1
3. `arc-core-types/src/receipt.rs` — touched by 1.2, 1.5, 15.1
4. `arc-store-sqlite/src/receipt_store/` — touched by 1.5, 12.2, 19.1, 19.3
5. `arc-cli/src/trust_control/` — touched by 1.1, 1.3, 1.4

**Recommendation**: Phase 1 (structural security) must be done serially due to kernel contention. Phase 2 (types) can parallelize 2.1, 2.2, then sequence 2.3, 2.4. Phase 3+ (guards/SDKs) parallelizes freely once Phase 2 types are stable.

---

**Last Updated**: 2026-04-16 15:55 UTC (post Wave 1b)
**Next Review**: After Wave 2 parallel cluster lands (phases 7.2-7.4, 12.1, 0.4, 17.6, 3.1, 5.6)

## Known Pre-existing Test Failures (not caused by Wave 1 work)

The following arc-kernel lib tests fail on both the Wave-1 tree and the
baseline immediately prior to Wave 1b. They are orthogonal to the
Wave-1 feature work and must be investigated independently:

- `checkpoint::tests::validate_checkpoint_transparency_rejects_predecessor_fork` — checkpoint_seq 3 does not immediately follow predecessor 1 (continuity-error text mismatch)
- `kernel::tests::governed_call_chain_receipt_follows_asserted_observed_verified_execution_order` — expected `Array []` got `Null`
- `receipt_support::tests::governed_request_metadata_marks_validated_upstream_call_chain_proof_as_verified` — `governed_transaction_diagnostics` unexpectedly present
- `session::tests::duplicate_inflight_request_is_rejected` — expected `SessionError::DuplicateInflightRequest` not matched

Treat as a dedicated debug task before any further arc-kernel feature work touches these modules.
