# Chio Roadmap Execution Matrix

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
| 0.1 | Publish Python SDKs to PyPI | PARTIAL | `sdks/python/chio-sdk-python/pyproject.toml` exists with metadata; no CI publish workflow found (`.github/workflows/publish-python.yml` missing) | CI/CD pipeline for automatic PyPI publishing on git tag |
| 0.2 | Publish TypeScript SDKs to npm | PARTIAL | `sdks/typescript/packages/{elysia,express,fastify,node-http}/package.json` exist with npm metadata; `.github/workflows/publish-typescript.yml` missing | CI/CD pipeline for npm registry publishing |
| 0.3 | MockArcClient for Testing | SHIPPED | Commit 788f69c: `sdks/python/chio-sdk-python/src/chio_sdk/testing.py` with `MockArcClient`, `allow_all()`, `deny_all()`, `with_policy()` factories; `tests/test_mock_client.py` ✓ | — |
| 0.4 | Pre-Built Binary Distribution | MISSING | No `.github/workflows/release-binaries.yml`; no `Dockerfile.sidecar`; no Homebrew tap | Cross-platform binary builds, Homebrew formula, Docker image |
| 0.5 | Error Message Improvements | SHIPPED | Commit 224a05c: enriched Deny verdict with structured context (scope, guard evidence, next-steps) | — |

---

## Phase 1: Structural Security Fixes

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 1.1 | Execution Nonces (TOCTOU Fix) | MISSING | No `chio-kernel/src/execution_nonce.rs` found; no grep matches for `ExecutionNonce` type | Implement nonce generation, validation, and store trait |
| 1.2 | Trust Level Taxonomy | SHIPPED | Commit 27488eb: `crates/chio-core-types/src/receipt.rs` contains `pub enum TrustLevel { Mediated, Verified, Advisory }` with field on `ChioReceipt` and `ChildRequestReceiptBody` ✓ | — |
| 1.3 | WASM Guard Module Signing | SHIPPED | Commit 3e258a3: Ed25519 signing for WASM guard modules at load | — |
| 1.4 | Emergency Kill Switch | SHIPPED | Commit 225193d: emergency_stop/resume on kernel + HTTP endpoints | — |
| 1.5 | Multi-Tenant Receipt Isolation | MISSING | `tenant_id` appears only in test config (federated_issue.rs, provider_admin.rs); NOT on `ChioReceipt` or `receipt_store` (5 test-only matches in chio-cli) | Add tenant_id field to receipt, modify receipt store SQL, enforce WHERE clause |

---

## Phase 2: Core Type Evolution

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 2.1 | New ToolAction Variants | SHIPPED | Commit f5a8a58: `crates/chio-guards/src/action.rs` contains `ToolAction::CodeExecution { language, code }`, `BrowserAction { verb, target }`, `DatabaseQuery { database, query }`, `ExternalApiCall { service, endpoint }`, `MemoryWrite { store, key }`, `MemoryRead { store, key }`; extraction heuristics in `extract_action()` ✓ | — |
| 2.2 | New Constraint Variants | SHIPPED | Commit f6a8820: 11 new Constraint variants (TableAllowlist, ColumnDenylist, MaxRowsReturned, OperationClass, AudienceAllowlist, ContentReviewTier, MaxTransactionAmountUsd, RequireDualApproval, ModelConstraint, MemoryStoreAllowlist, MemoryWriteDenyPatterns) + kernel request_matching enforcement for Audience/Memory variants | — |
| 2.3 | ModelConstraint Implementation | MISSING | No `ModelMetadata`, `ModelSafetyTier`, or `ModelConstraint` types found in chio-core-types; no kernel evaluation logic | Define types, add constraint evaluator in kernel, test against model_metadata |
| 2.4 | Plan-Level Evaluation | MISSING | No `PlannedToolCall`, `PlanEvaluationRequest`, `PlanEvaluationResponse` types; no `evaluate_plan()` kernel method; no `/evaluate-plan` endpoint | Plan types in chio-core-types, kernel method, HTTP route, verdict per step |

---

## Phase 3: Content Safety and Human-in-the-Loop

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 3.1 | PromptInjectionGuard | MISSING | No `chio-guards/src/prompt_injection.rs` or `text_utils.rs` found; 0 grep matches for PromptInjectionGuard | Port from ClawdStrike, 6-signal detector, canonicalization, fingerprint dedup |
| 3.2 | JailbreakGuard | MISSING | No `chio-guards/src/jailbreak.rs` or `jailbreak_detector.rs` | 4-layer detector (heuristic, statistical, ML, LLM), scoring layer |
| 3.3 | Output Sanitizer Completion | PARTIAL | `crates/chio-guards/src/response_sanitization.rs` exists; `post_invocation.rs` exists; no evidence of secret detection, Luhn validation, entropy scanning, allowlist/denylist overlap resolution | Extend response_sanitization with full PII/secret/entropy detection pipeline |
| 3.4 | HITL: Kernel Verdict Extension | MISSING | No `Verdict::PendingApproval` variant; no `chio-kernel/src/approval.rs`; no approval guard, store, HTTP routes | PendingApproval verdict variant, ApprovalGuard, approval store, resume flow, webhook firing |
| 3.5 | HITL Persistence Backend | MISSING | No `chio-store-sqlite/src/approval_store.rs` or `batch_approval_store.rs`; no approval store traits | SQLite backend for approval persistence, kernel reload on restart |
| 3.6 | Approval Channels | MISSING | No `chio-kernel/src/approval_channels.rs`; no `ApprovalChannel` trait or webhook implementation | Webhook, Slack, dashboard channels; trait abstraction |

---

## Phase 4: Flagship Integration – chio-code-agent

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 4.1 | chio-code-agent Python Package | MISSING | No `sdks/python/chio-code-agent/` directory | Package scaffold, CodeAgent wrapper, default policy, tests |
| 4.2 | MCP Sidecar Wrapper for Coding Agents | MISSING | No `arc mcp serve --preset code-agent`; no `crates/chio-cli/src/policies/code_agent.yaml` | CLI preset, bundled policy, MCP server wrapping |
| 4.3 | Migration Guide: MCP to Chio | MISSING | No `docs/guides/MIGRATING-FROM-MCP.md` | Step-by-step integration guide |

---

## Phase 5: ClawdStrike Guard Absorption (Remaining)

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 5.1 | ComputerUseGuard | MISSING | No `chio-guards/src/computer_use.rs` | Action-type allowlisting, Observe/Guardrail/FailClosed modes |
| 5.2 | InputInjectionCapabilityGuard | MISSING | No `chio-guards/src/input_injection.rs` | Input-type restrictions, postcondition probe validation |
| 5.3 | RemoteDesktopSideChannelGuard | MISSING | No `chio-guards/src/remote_desktop.rs` | Per-channel enable/disable, transfer size limits |
| 5.4 | SpiderSense Embedding Detector | MISSING | No `chio-guards/src/spider_sense.rs`; no `data/spider_sense_patterns.json` | Cosine similarity detector, pattern database |
| 5.5 | Policy Engine: Guard Compilation | PARTIAL | `crates/chio-policy/src/` exists (11 files); no evidence of extended compiler covering all 12 guard types or 7 ported rulesets | Complete guard type compilation, port 7 built-in rulesets |
| 5.6 | Custom Guard Registry: WASM Merge | MISSING | No `load_guards_from_policy()` in chio-wasm-guards; no `placeholders.rs` with env var resolution | Policy-driven WASM guard loading, placeholder resolution, capability intersection |

---

## Phase 6: Agent Framework SDKs

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 6.1 | chio-crewai | MISSING | No `sdks/python/chio-crewai/` directory | BaseTool wrapper, per-role scoping, delegation, PyPI publish |
| 6.2 | chio-autogen | MISSING | No `sdks/python/chio-autogen/` directory | Function registration wrapper, group chat governance |
| 6.3 | chio-llamaindex | MISSING | No `sdks/python/chio-llamaindex/` directory | FunctionTool wrapper, RAG pipeline scoping |
| 6.4 | @chio-protocol/ai-sdk | MISSING | No `sdks/typescript/packages/ai-sdk/` directory | Vercel AI SDK wrapper, streaming support |

---

## Phase 7: Data Layer Guards

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 7.1 | SqlQueryGuard | SHIPPED | Commit b3666a9: chio-data-guards crate with SqlQueryGuard | — |
| 7.2 | VectorDbGuard | MISSING | No `vector_guard.rs` in chio-data-guards | Collection scoping, operation class, top_k limits |
| 7.3 | WarehouseCostGuard | MISSING | No `warehouse_cost_guard.rs`; no `CostDimension::WarehouseQuery` in chio-metering | Pre-execution cost estimation, MaxBytesScanned/MaxCostPerQuery |
| 7.4 | QueryResultGuard (Post-Invocation) | MISSING | No `result_guard.rs` | Row count enforcement, column redaction, PII pattern matching |

---

## Phase 8: Code Execution Guards

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 8.1 | CodeExecutionGuard | MISSING | No `chio-guards/src/code_execution.rs` | Language allowlist, network control, timeout, dangerous module detection |
| 8.2 | BrowserAutomationGuard | MISSING | No `chio-guards/src/browser_automation.rs` | Domain allowlists, action restrictions, credential detection |

---

## Phase 9: Networking – Envoy ext_authz

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 9.1 | gRPC ext_authz Adapter | SHIPPED | Commit 7f4d0d7: chio-envoy-ext-authz crate with EnvoyKernel trait, Check RPC, vendored envoy v3 protos | — |
| 9.2 | Istio Integration Example | MISSING | No `examples/istio-ext-authz/` | Reference AuthorizationPolicy, K8s manifests |

---

## Phase 10: Orchestration Integrations

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 10.1 | chio-temporal (Python) | MISSING | No `sdks/python/chio-temporal/` | ChioActivityInterceptor, WorkflowGrant, receipt aggregation |
| 10.2 | chio-lambda-extension | MISSING | No `sdks/lambda/` directory | Lambda Extension binary, pre-built Layer |
| 10.3 | chio-langgraph | MISSING | No `sdks/python/chio-langgraph/` | chio_node wrapper, approval node, depends on Phase 3 HITL |

---

## Phase 11: SaaS, Communication, and Streaming

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 11.1 | Content-Review Guard | MISSING | No `chio-guards/src/content_review.rs` | Pre-invocation PII/tone/profanity, per-service config |
| 11.2 | chio-streaming (Kafka) | MISSING | No `sdks/python/chio-streaming/` | ChioConsumerMiddleware, DLQ governance, transactional commit |
| 11.3 | IaC Governance (chio-iac) | MISSING | No `sdks/python/chio-iac/` | Terraform CLI wrapper, Pulumi decorators |

---

## Phase 12: SIEM and Observability Completion

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 12.1 | Missing SIEM Exporters | PARTIAL | `crates/chio-siem/src/exporters/` exists with some exporters; no Datadog, Sumo Logic, webhook, or alerting exporters found | Port 4 missing exporters from ClawdStrike |
| 12.2 | OCSF Receipt Format | SHIPPED | Commit dec8378: chio-siem/src/ocsf.rs with OCSF 3002 mapping + OcsfExporter backend | — |
| 12.3 | LangSmith / LangFuse Bridge | MISSING | No `sdks/python/chio-observability/` | Receipts as enriched spans in observability platforms |

---

## Phase 13: Async Guard Runtime and Threat Intelligence

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 13.1 | AsyncGuardAdapter Infrastructure | MISSING | No `chio-guards/src/external/` with circuit breaker, cache, retry modules | ExternalGuard trait, AsyncGuardAdapter, circuit breaker pattern |
| 13.2 | Cloud Guardrail Adapters | MISSING | No Bedrock, Azure, or Vertex safety adapters | 3 cloud guardrail implementations |
| 13.3 | Threat Intelligence Guards | MISSING | No `threat_intel/` directory with VirusTotal, Safe Browsing, Snyk | 3 threat intel ExternalGuard impls |

---

## Phase 14: Portable Kernel (WASM)

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 14.1 | chio-kernel-core Extraction | MISSING | No `crates/chio-kernel-core/` directory; no no_std+alloc kernel | Extract portable kernel subset, WASM compilation |
| 14.2 | Browser Bindings | MISSING | No `chio-kernel-browser` crate | wasm-bindgen bindings, Web Crypto support |
| 14.3 | Mobile FFI (iOS/Android) | MISSING | No `chio-kernel-mobile` crate | UniFFI bindings for Swift/Kotlin |

---

## Phase 15: Compliance

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 15.1 | FIPS Crypto Path | MISSING | `crates/chio-core-types/src/crypto.rs` uses Ed25519 (ed25519-dalek); no `SigningBackend` trait, no `aws-lc-rs` support, no P-256/P-384 option | FIPS trait abstraction, P-256/P-384 backend, algorithm identifier in serialization |
| 15.2 | NIST AI RMF Mapping | SHIPPED | Commit 98252dd: `docs/compliance/nist-ai-rmf.md` created with Govern/Map/Measure/Manage function mapping ✓ | — |
| 15.3 | PCI DSS v4.0 Mapping | SHIPPED | Commit 98252dd: `docs/compliance/pci-dss-v4.md` created with 12 requirement groups mapped ✓ | — |
| 15.4 | ISO 42001 Mapping | SHIPPED | Commit 98252dd: `docs/compliance/iso-42001.md` created with clause-level mapping ✓ | — |
| 15.5 | OWASP LLM Top 10 Coverage Matrix | SHIPPED | Commit 98252dd: `docs/compliance/owasp-llm-top-10.md` created with risk-to-control mapping ✓ | — |

---

## Phase 16: Economic Layer Developer Guide and Budget Hierarchy

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 16.1 | Economic Layer Developer Guide | SHIPPED | Commit f7c738f: docs/guides/ECONOMIC-LAYER.md | — |
| 16.2 | Hierarchical Budget Governance | SHIPPED | Commit 8234a4d: chio_metering::budget_hierarchy BudgetTree with org/dept/team/agent rollups; stateless policy with caller-supplied SpendSnapshot | — |

---

## Phase 17: Remaining Orchestration and Pipeline Integrations

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 17.1 | chio-prefect | MISSING | No `sdks/python/chio-prefect/` | @chio_task/@chio_flow decorators, Prefect Events |
| 17.2 | chio-dagster | MISSING | No `sdks/python/chio-dagster/` | @chio_asset decorator, partition-scoped capabilities |
| 17.3 | chio-airflow | MISSING | No `sdks/python/chio-airflow/` | ChioOperator wrapper, @chio_task decorator |
| 17.4 | chio-ray | MISSING | No `sdks/python/chio-ray/` | @chio_remote decorator, ChioActor base class |
| 17.5 | K8s Job Controller Extension | MISSING | No `sdks/k8s/controller/` | Job lifecycle capability grants |
| 17.6 | Cloud Run / ECS Sidecar Reference | MISSING | No `deploy/` directory with Cloud Run, ECS, Azure configs | Reference deployment manifests |

---

## Phase 18: Agent Memory Governance

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 18.1 | Memory Write/Read Guards | MISSING | No `chio-guards/src/memory_governance.rs` | Guards for MemoryWrite/MemoryRead ToolActions |
| 18.2 | Memory Entry Provenance | MISSING | No `chio-kernel/src/memory_provenance.rs` | Hash chain linking writes to capability IDs |

---

## Phase 19: Future Moats (Near-Term)

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 19.1 | Receipt Compliance Scoring | MISSING | No `chio-kernel/src/compliance_score.rs`; no `/compliance/score` endpoint; 0 grep matches for compliance_score | Scoring model (0-1000), CLI/HTTP surface |
| 19.2 | Agent Behavioral Profiling | PARTIAL | `crates/chio-guards/src/behavioral_sequence.rs` exists (baseline behavioral guard); no `behavioral_profile.rs` with anomaly detection and EMA | Extend BehavioralFeedReport with EMA/z-score anomaly guard |
| 19.3 | Regulatory API | MISSING | No `chio-http-core/src/regulatory_api.rs`; no `/regulatory/receipts` endpoint | Read-only API with SignedExportEnvelope wrapping |

---

## Phase 20: Future Moats (Medium-Term)

| Story | Title | Status | Evidence | Gap |
|-------|-------|--------|----------|-----|
| 20.1 | Agent Passport: Trust-Tier Synthesis and WASM | PARTIAL | `crates/chio-credentials/src/passport.rs` exists with core passport system; no `trust_tier.rs` with compliance score synthesis; no `chio-kernel-core/src/passport_verify.rs` (blocked on 14.1) | trust_tier field synthesis from compliance+behavioral; WASM verification (blocked on Phase 14) |
| 20.2 | Agent Insurance Protocol | MISSING | No `chio-underwriting/src/premium.rs`; no `chio-market/src/insurance_flow.rs` | Premium pricing from receipt score, end-to-end claims flow |
| 20.3 | Cross-Kernel Federation: Bilateral Co-Signing | MISSING | `crates/chio-federation/src/` exists (core federation shipped); no `bilateral.rs` or `trust_establishment.rs` | bilateral receipt co-signing, mTLS key exchange between kernels |
| 20.4 | Capability Marketplace | PARTIAL | `crates/chio-listing/src/` and `chio-open-market/src/` exist; no `bidding.rs` with bid/ask protocol | Extend discovery/comparison, add bidding protocol |

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

## Wave 2 Results (2026-04-16)

**All 7 Wave 2 stories SHIPPED.** Commits on `project/full-roadmap`:

| # | Story | Commit | Notes |
|---|-------|--------|-------|
| 7.2 | VectorDbGuard | `102c805` | chio-data-guards: vector_guard.rs + tests |
| 7.3 | WarehouseCostGuard | `5a0da48` | + `CostDimension::WarehouseQuery` in chio-metering |
| 7.4 | QueryResultGuard | `d8e4514` | Shipped as transform + pipeline hook; kernel post-invocation surface pending |
| 3.1 | PromptInjectionGuard | `3d55e18` | 6-signal detector, lru dedup, sha2 hashing, 225 tests |
| 17.6 | Cloud Run/ECS/Azure | `8a0b933` | deploy/{cloud-run,ecs,azure}/ + README |
| 12.1 | SIEM exporters + alerting | `4c8472b` | Datadog + Sumo Logic + webhook + PagerDuty/OpsGenie |
| 5.6 | WASM policy-driven loading | `c381458` | Placeholders + capability intersection + signed-module verification |

**Post-Wave adjacents:**

- `ed2614f` — **TEE attested checkpoint binding scope** — `arc.nitro.attested_checkpoint_binding.v1` shape doc + kernel scoped verified runtime attestation record + CLI issuance returns verified record without runtime policy.
- `56af8a9` — **cargo fmt workspace sweep** — 36 files, no behavior change.

**Integration gate**: `cargo check --workspace --all-targets` clean. Focused test suites across chio-data-guards + chio-siem + chio-guards + chio-metering + chio-core-types: **654/654 passed, 0 failed, 2 ignored**. Kernel+appraisal: **258 passed, 4 failed** (4 = pre-existing failures unchanged by Wave 2).

**Not shipped in Wave 2**: 0.4 Pre-Built Binary Distribution (CI-only; deferred pending GitHub Actions secret config).

---

## Next Candidates: Wave 3

**Criteria**: kernel-contended work now unblocked. Another session previously held parallel work on chio-kernel/mod.rs + chio-appraisal has been quiesced; main is clean. Serialize within the kernel hot-file cluster.

### Wave 3a: Parallelizable Pre-Kernel (no hot-file contention)
*Can start immediately.*

1. **15.1 FIPS Crypto Path** — `SigningBackend` trait in chio-core-types/src/crypto.rs; P-256/P-384 backend. No kernel write.
2. **0.4 Pre-Built Binary Distribution** — `.github/workflows/release-binaries.yml`, `Dockerfile.sidecar`, Homebrew formula. Pure CI/infra.
3. **13.x Observability hardening** — chio-metering dashboards, receipt-query CLI. Stays within chio-metering + chio-cli.

### Wave 3b: Kernel Cluster (serialize)
*One at a time; each completes before the next spawns.*

4. **2.3 ModelConstraint Implementation** — deepen `chio-kernel/src/kernel/mod.rs` + `request_matching.rs` evaluation for already-shipped ModelConstraint variant.
5. **2.4 Plan-Level Evaluation** — new `chio-core-types::PlannedToolCall`, kernel `evaluate_plan()`, HTTP route.
6. **3.4 HITL Verdict + 3.5 Persistence + 3.6 Channels** — cluster; all three share `Verdict::PendingApproval` and ApprovalGuard. Serialize within cluster.

### Wave 3c: Post-Kernel
*After 3b completes.*

7. **Debug 4 pre-existing chio-kernel test failures** (checkpoint / session / receipt_support / governed_call_chain order).
8. **14.x WASM kernel** — chio-kernel-core extraction.
9. **10.3 chio-langgraph** — after 3.4-3.6 HITL shapes stabilize.

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
    └─ 3.4/3.5/3.6 (HITL) ──→ 10.3 (chio-langgraph)

PHASE 3+ (Requires 2.*)
├─ 3.1, 3.2 (Guards) ──→ 3.3 (Sanitizer) ──→ content plane
├─ 5.* (Guard Absorption, depends on 2.1 ToolAction)
├─ 6.* (Framework SDKs, depends on Phase 0 publishing + 2)
├─ 7.* (Data Guards, depends on 2 Constraints + 2.1 ToolAction)
└─ 8.* (Code Exec Guards, depends on 2.1 ToolAction)

PHASE 4 (Flagship SDK, depends on Phase 0 publishing)
└─ 4.1, 4.2, 4.3 (chio-code-agent ecosystem)

PHASE 9 (Envoy, no deps) ──→ standalone

PHASE 14 (WASM Kernel, depends on 1,2,3)
└─ 14.1 (chio-kernel-core) ──→ 14.2 (Browser), 14.3 (Mobile)
    └─ 20.1 (Agent Passport, depends on 14.1 + 19.1/19.2)
```

---

## Hot File Serialization Risk Matrix

**High contention** (serialize work):
1. `chio-kernel/src/kernel/mod.rs` — touched by 1.1, 1.2, 1.4, 1.5, 2.2, 2.3, 2.4, 3.4, 3.5, 8.1, 8.2, 14.1, 18.2, 20.1, 20.3
2. `chio-core-types/src/capability.rs` — touched by 1.2, 2.2, 2.3, 15.1
3. `chio-core-types/src/receipt.rs` — touched by 1.2, 1.5, 15.1
4. `chio-store-sqlite/src/receipt_store/` — touched by 1.5, 12.2, 19.1, 19.3
5. `chio-cli/src/trust_control/` — touched by 1.1, 1.3, 1.4

**Recommendation**: Phase 1 (structural security) must be done serially due to kernel contention. Phase 2 (types) can parallelize 2.1, 2.2, then sequence 2.3, 2.4. Phase 3+ (guards/SDKs) parallelizes freely once Phase 2 types are stable.

---

**Last Updated**: 2026-04-16 21:20 UTC (post Wave 2 + TEE binding scope)
**Next Review**: After Wave 3a parallel cluster lands (15.1 FIPS, 0.4 binaries, 13.x observability)

## Known Pre-existing Test Failures (not caused by Wave 1 work)

The following chio-kernel lib tests fail on both the Wave-1 tree and the
baseline immediately prior to Wave 1b. They are orthogonal to the
Wave-1 feature work and must be investigated independently:

- `checkpoint::tests::validate_checkpoint_transparency_rejects_predecessor_fork` — checkpoint_seq 3 does not immediately follow predecessor 1 (continuity-error text mismatch)
- `kernel::tests::governed_call_chain_receipt_follows_asserted_observed_verified_execution_order` — expected `Array []` got `Null`
- `receipt_support::tests::governed_request_metadata_marks_validated_upstream_call_chain_proof_as_verified` — `governed_transaction_diagnostics` unexpectedly present
- `session::tests::duplicate_inflight_request_is_rejected` — expected `SessionError::DuplicateInflightRequest` not matched

Treat as a dedicated debug task before any further chio-kernel feature work touches these modules.
