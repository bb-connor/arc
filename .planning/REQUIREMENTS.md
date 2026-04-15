# Requirements: ARC

**Defined:** 2026-03-27
**Latest completed milestone:** v3.14 Universal Fabric and Kernel Convergence
(completed locally and archived locally 2026-04-14)
**Latest archived milestone:** v3.14 Universal Fabric and Kernel Convergence
(completed locally and archived locally 2026-04-14)
**Most recent implemented milestone:** v3.14 Universal Fabric and Kernel
Convergence (completed locally and archived locally 2026-04-14)
**Active milestone:** v3.15 Universal Protocol Fabric Realization
**Planned milestones:** v3.0 through v3.15 (Universal Security Kernel era)
**Deferred milestone:** v2.71 Web3 Live Activation (pending external inputs)
**Core Value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust across organizational boundaries.

## Ship Readiness Requirements (v2.66-v2.73)

### v2.66 Test Coverage for Untested Crates

- [x] **TEST-01**: arc-hosted-mcp has unit tests covering session lifecycle creation, resumption, and expiry
- [x] **TEST-02**: arc-hosted-mcp has unit tests covering multi-tenant isolation between concurrent sessions
- [x] **TEST-03**: arc-hosted-mcp has unit tests covering auth flows (bearer, JWT, OAuth with PKCE)
- [x] **TEST-04**: arc-hosted-mcp has unit tests covering error paths and fail-closed behavior
- [x] **TEST-05**: arc-wall has unit tests covering validation rule enforcement for all rule types present in the bounded ARC-Wall lane
- [x] **TEST-06**: arc-wall has unit tests covering edge cases and boundary conditions
- [x] **TEST-07**: arc-wall has unit tests covering barrier review logic and control-room decisions in the shipped bounded companion-product path
- [x] **TEST-08**: arc-siem has unit tests covering Splunk HEC export formatting and delivery
- [x] **TEST-09**: arc-siem has unit tests covering Elasticsearch bulk export formatting and delivery
- [x] **TEST-10**: arc-siem has unit tests covering DLQ behavior on export failure
- [x] **TEST-11**: arc-siem has unit tests covering per-exporter rate limiting
- [x] **TEST-12**: Cross-crate integration tests exercise the real hosted-mcp/kernel -> siem seam and the ARC-Wall companion receipt -> siem seam on the shared ARC substrate
- [x] **TEST-13**: Cross-crate integration tests verify fail-closed behavior across the real crate boundaries that exist today

### v2.67 Kernel Panic Hardening

- [x] **HARDEN-01**: All 22 literal `panic!` calls in `arc-kernel/src` are audited and classified, including whether they are test-only invariant assertions or external-input reachable
- [x] **HARDEN-02**: The audited production kernel exposes no input-dependent literal panics, and externally triggered framing/parser failures return typed errors without changing fail-closed posture
- [x] **HARDEN-03**: ARC's canonical JSON transport returns structured errors for malformed input, missing required fields, wrong field types, and mid-frame disconnects instead of crashing the kernel
- [x] **HARDEN-04**: No literal `panic!` macro remains under `crates/arc-kernel/src`; test-only invariant assertions use explicit non-`panic!` assertion style so panic scans only flag real regressions
- [x] **HARDEN-05**: Adversarial input tests prove the kernel transport does not crash on malformed canonical JSON `AgentMessage` payloads
- [x] **HARDEN-06**: Adversarial input tests prove the kernel transport does not crash on truncated messages
- [x] **HARDEN-07**: Adversarial input tests prove the kernel transport does not crash on wrong-type or missing-field payloads

### v2.68 Quality Infrastructure

- [x] **QUAL-01**: proptest property tests cover Ed25519 sign/verify roundtrips with arbitrary payloads
- [x] **QUAL-02**: proptest property tests cover monetary arithmetic (budget overflow, underflow, precision)
- [x] **QUAL-03**: proptest property tests cover capability attenuation subset relationships
- [x] **QUAL-04**: Criterion benchmarks establish baseline for Ed25519 signature verification throughput
- [x] **QUAL-05**: Criterion benchmarks establish baseline for canonical JSON serialization
- [x] **QUAL-06**: Criterion benchmarks establish baseline for Merkle proof generation and verification
- [x] **QUAL-07**: Criterion benchmarks establish baseline for capability validation latency
- [x] **QUAL-08**: Code coverage reporting via cargo-tarpaulin is wired into CI
- [x] **QUAL-09**: Coverage reports are generated and stored in coverage/ directory
- [x] **QUAL-10**: A meaningful coverage floor is set based on actual measured coverage

### v2.69 CI Gate and Release Qualification

Closeout note: on 2026-04-12 the pushed `origin/main` commit was
operator-confirmed to have passed hosted `CI`, while hosted `Release
Qualification` still failed. The remaining release-qualification and tagging
requirements were explicitly accepted as known gaps to unblock `v2.70`.

- [x] **CI-01**: ci.yml runs green in hosted GitHub Actions on stable Rust and MSRV
- [ ] **CI-02**: release-qualification.yml runs green in hosted GitHub Actions
- [ ] **CI-03**: Conformance wave 1-5 all pass across JS, Python, Go peers in hosted environment
- [ ] **CI-04**: qualify-release.sh produces signed qualification artifacts in hosted CI
- [ ] **CI-05**: Release candidate is tagged after hosted observation confirms all gates green

### v2.70 Developer Experience and Packaging

- [x] **DX-01**: Multi-stage Dockerfile produces minimal Alpine-based arc CLI image
- [x] **DX-02**: Docker Compose example wraps an MCP server with ARC policy enforcement
- [x] **DX-03**: Working example shows arc mcp serve as tool provider for Claude via Anthropic SDK
- [x] **DX-04**: Working example wraps ARC-governed tool server as a LangChain tool
- [x] **DX-05**: README updated with container quickstart, framework examples, and 5-minute-to-production path

### v2.71 Web3 Live Activation

Deferral note: on 2026-04-12 this milestone was deferred because repo-local
execution remains blocked on external Base Sepolia operator credentials,
reviewed live-chain rollout artifacts, and OpenTimestamps tooling.

- [ ] **WEB3-01**: ARC contracts deployed to Base Sepolia testnet
- [ ] **WEB3-02**: End-to-end flow runs: capability -> tool call -> receipt -> settlement with test tokens
- [ ] **WEB3-03**: OpenTimestamps super-root aggregation wired into integration tests
- [ ] **WEB3-04**: Solana memo publication added to conformance harness
- [ ] **WEB3-05**: Cross-chain proof bundle verification passes across EVM, Bitcoin, and Solana lanes
- [ ] **WEB3-06**: Multi-chain qualification report documents all three chains working
- [ ] **WEB3-07**: Operator runbook covers enabling and monitoring web3 settlement

### v2.72 Distributed Systems and Federation

- [x] **DIST-01**: Trust-control service supports Raft-based consensus replication
- [x] **DIST-02**: Raft implementation handles split-brain, log compaction, and snapshot transfer
- [x] **DIST-03**: Operators can publish open-admission federation policies with anti-sybil controls
- [x] **DIST-04**: Reputation-gated federation entry is supported
- [x] **DIST-05**: SCIM 2.0 endpoint supports automatic provisioning from external IdP
- [x] **DIST-06**: SCIM 2.0 endpoint supports automatic deprovisioning from external IdP
- [x] **DIST-07**: Trust-control deployed across 3 regions proves consistency under network partition
- [x] **DIST-08**: Replication lag is measured and documented under partition scenarios

### v2.73 Formal Verification

- [x] **FORMAL-01**: Every sorry placeholder in Lean 4 tree is inventoried and classified
- [x] **FORMAL-02**: Attenuation monotonicity is proven in Lean 4
- [x] **FORMAL-03**: Delegation chain integrity is proven in Lean 4
- [x] **FORMAL-04**: Budget non-negative invariant is proven in Lean 4
- [x] **FORMAL-05**: Merkle inclusion soundness is proven in Lean 4
- [x] **FORMAL-06**: Checkpoint consistency is proven in Lean 4
- [x] **FORMAL-07**: Receipt immutability is proven in Lean 4
- [x] **FORMAL-08**: Lean 4 lake build runs in CI and fails on any new sorry in proven modules

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| TEST-01 | Phase 273 | Complete |
| TEST-02 | Phase 273 | Complete |
| TEST-03 | Phase 273 | Complete |
| TEST-04 | Phase 273 | Complete |
| TEST-05 | Phase 274 | Complete |
| TEST-06 | Phase 274 | Complete |
| TEST-07 | Phase 274 | Complete |
| TEST-08 | Phase 275 | Complete |
| TEST-09 | Phase 275 | Complete |
| TEST-10 | Phase 275 | Complete |
| TEST-11 | Phase 275 | Complete |
| TEST-12 | Phase 276 | Complete |
| TEST-13 | Phase 276 | Complete |
| HARDEN-01 | Phase 277 | Complete |
| HARDEN-02 | Phase 278 | Complete |
| HARDEN-03 | Phase 278 | Complete |
| HARDEN-04 | Phase 279 | Complete |
| HARDEN-05 | Phase 280 | Complete |
| HARDEN-06 | Phase 280 | Complete |
| HARDEN-07 | Phase 280 | Complete |
| QUAL-01 | Phase 281 | Complete |
| QUAL-02 | Phase 281 | Complete |
| QUAL-03 | Phase 281 | Complete |
| QUAL-04 | Phase 282 | Complete |
| QUAL-05 | Phase 282 | Complete |
| QUAL-06 | Phase 282 | Complete |
| QUAL-07 | Phase 282 | Complete |
| QUAL-08 | Phase 283 | Complete |
| QUAL-09 | Phase 283 | Complete |
| QUAL-10 | Phase 283 | Complete |
| CI-01 | Phase 284 | Complete |
| CI-02 | Phase 284 | Accepted gap |
| CI-03 | Phase 285 | Accepted gap |
| CI-04 | Phase 286 | Accepted gap |
| CI-05 | Phase 286 | Accepted gap |
| DX-01 | Phase 287 | Complete |
| DX-02 | Phase 287 | Complete |
| DX-03 | Phase 288 | Complete |
| DX-04 | Phase 289 | Complete |
| DX-05 | Phase 290 | Complete |
| WEB3-01 | Phase 291 | Deferred |
| WEB3-02 | Phase 291 | Deferred |
| WEB3-03 | Phase 292 | Deferred |
| WEB3-04 | Phase 293 | Deferred |
| WEB3-05 | Phase 293 | Deferred |
| WEB3-06 | Phase 294 | Deferred |
| WEB3-07 | Phase 294 | Deferred |
| DIST-01 | Phase 295 | Complete |
| DIST-02 | Phase 295 | Complete |
| DIST-03 | Phase 296 | Complete |
| DIST-04 | Phase 296 | Complete |
| DIST-05 | Phase 297 | Complete |
| DIST-06 | Phase 297 | Complete |
| DIST-07 | Phase 298 | Complete |
| DIST-08 | Phase 298 | Complete |
| FORMAL-01 | Phase 299 | Complete |
| FORMAL-02 | Phase 300 | Complete |
| FORMAL-03 | Phase 300 | Complete |
| FORMAL-04 | Phase 300 | Complete |
| FORMAL-05 | Phase 301 | Complete |
| FORMAL-06 | Phase 301 | Complete |
| FORMAL-07 | Phase 301 | Complete |
| FORMAL-08 | Phase 302 | Pending |

**Coverage:**
- Ship readiness requirements (v2.66-v2.73): 63 total, 63 mapped, 0 unmapped
- Foundation and adoption requirements (v2.80-v2.83): 52 total, 52 mapped, 0 unmapped

---

## v2.80 Core Decomposition and Async Kernel

### Phase 303: arc-core Crate Decomposition

- [x] **DECOMP-01**: A new `arc-core-types` crate contains capabilities, receipts, cryptographic signing, canonical JSON, and scope types -- the minimal set every ARC crate needs
- [x] **DECOMP-02**: Domain types (credit, exposure, facility, bond, liability, market, governance, listing, appraisal, federation) are extracted into separate domain crates that depend on `arc-core-types` rather than living in `arc-core`
- [x] **DECOMP-03**: All 25 dependent crates compile and pass tests against the decomposed `arc-core-types` without behavior changes
- [x] **DECOMP-04**: Incremental compile time for a single-file change in `arc-core-types` is measurably faster than the same change in the monolithic `arc-core`

### Phase 304: Mega-File Module Decomposition

- [x] **DECOMP-05**: `trust_control.rs` (21K lines) is decomposed into focused modules (federation, passport, settlement, SCIM, HTTP routes, types) with no public API changes
- [x] **DECOMP-06**: `arc-kernel/src/lib.rs` (11.7K lines) is split so the test module lives in its own file and kernel subsystems are in separate modules
- [x] **DECOMP-07**: `arc-cli/src/main.rs` (10.3K lines) is decomposed into per-subcommand modules with a thin dispatch entry point
- [x] **DECOMP-08**: `receipt_store.rs` (9.8K lines) and `runtime.rs` (6.4K lines) are decomposed into focused modules
- [x] **DECOMP-09**: No file under `crates/` exceeds 3,000 lines of non-test code after decomposition

### Phase 305: Async Kernel Migration

- [x] **ASYNC-01**: `ArcKernel::evaluate_tool_call` is an async function taking `&self` instead of `&mut self`
- [x] **ASYNC-02**: Session state, receipt log, and budget stores use interior mutability (`RwLock` or equivalent) so multiple tool calls can be evaluated concurrently
- [x] **ASYNC-03**: Two concurrent tool calls from different agents complete without serialization -- verified by a test that runs parallel evaluations
- [x] **ASYNC-04**: Existing synchronous test suite passes against the async kernel with no behavior changes beyond concurrency enablement

### Phase 306: Dependency Hygiene and Feature Gating

- [x] **DEPS-01**: `serde_yaml` (deprecated) is replaced with `serde_yml` across all three dependent crates (arc-cli, arc-control-plane, arc-policy)
- [x] **DEPS-02**: The workspace uses a single major version of `reqwest` (no dual 0.12 + 0.13 copies)
- [x] **DEPS-03**: Web3/alloy dependencies are gated behind a `web3` cargo feature flag so the kernel and core crates compile without the EVM stack when the feature is disabled
- [x] **DEPS-04**: `cargo tree -d` shows no duplicate crate versions for `reqwest`, `serde_yaml`, or `hashbrown`

---

## v2.81 Deployable ARC and Developer Onboarding

### Phase 307: Identity Resolution and Scaffolding

- [x] **ONBOARD-01**: README.md, CLI help text, crate doc comments, and all user-facing strings use "ARC" consistently -- no references to "CHIO" or conflicting name expansions
- [x] **ONBOARD-02**: `arc init` creates a working project scaffold with a default policy file, a hello-world tool server stub, and a Makefile/justfile that builds and runs the example
- [x] **ONBOARD-03**: `arc init` output includes next-step instructions that guide the developer to their first governed tool call

### Phase 308: SDK Publication

- [x] **SDK-01**: TypeScript SDK is published to npm as a stable release with typed client for capability requests, tool invocations, and receipt queries
- [x] **SDK-02**: Python SDK is published to PyPI as a stable release with typed client for capability requests, tool invocations, and receipt queries
- [x] **SDK-03**: Both SDKs include end-to-end examples that connect to a running ARC kernel and execute a governed tool call
- [x] **SDK-04**: SDK README files document installation, quickstart, and API reference with code samples

### Phase 309: Deployable Experience

- [x] **DEPLOY-01**: `docker compose up` in the examples directory starts an ARC kernel, a sample tool server, and a receipt viewer accessible at localhost
- [x] **DEPLOY-02**: The receipt viewer displays signed receipts with capability chain, guard decisions, and timestamps in a human-readable format
- [x] **DEPLOY-03**: A developer can execute `docker compose up`, call a governed tool via curl or SDK, and see the receipt appear in the viewer within 5 minutes of cloning the repo

### Phase 310: Progressive Tutorial and Framework Integration

- [x] **TUTORIAL-01**: A progressive tutorial exists covering: ARC concepts, writing a policy, wrapping a tool server, executing a governed call, reading a receipt, and delegating a capability
- [x] **TUTORIAL-02**: The Anthropic SDK example is rewritten to use the official TypeScript SDK instead of raw JSON-RPC
- [x] **TUTORIAL-03**: The LangChain example is rewritten to use the official Python SDK instead of raw subprocess invocation
- [x] **TUTORIAL-04**: An OpenAI-compatible example demonstrates ARC governance over function calling with the official SDK

---

## v2.82 Normative Protocol Specification and Conformance

### Phase 311: Wire Protocol Specification

- [x] **SPEC-01**: A normative protocol specification document defines the wire framing format (length-prefix encoding, byte order, maximum message size)
- [x] **SPEC-02**: JSON Schema definitions exist for every message type in the agent-kernel protocol (capability request, tool invocation, receipt, error, handshake)
- [x] **SPEC-03**: Sequence diagrams document the core protocol flows: initialization/handshake, capability issuance, tool invocation with receipt, delegation, and revocation
- [x] **SPEC-04**: The spec is written so a competent engineer could implement a compatible agent or kernel client without reading the Rust source code

### Phase 312: Version Negotiation and Error Taxonomy

- [x] **SPEC-05**: The protocol defines version negotiation rules: how client and server exchange supported versions, how disagreements are resolved, and when connections are rejected
- [x] **SPEC-06**: A normative error code taxonomy defines numeric codes, human-readable names, whether errors are transient or permanent, and retry guidance for each
- [x] **SPEC-07**: The error taxonomy covers at minimum: capability denied, capability expired, capability revoked, guard denied (with guard identity), budget exceeded, tool server error, internal error, version mismatch, and rate limited

### Phase 313: Threat Model and Security Specification

- [x] **SPEC-08**: A standalone threat model document enumerates attack vectors against the agent-kernel-tool trust boundary including: token theft, kernel impersonation, tool server escape, replay attacks, and denial of service
- [x] **SPEC-09**: Each identified threat maps to a mitigation (existing or planned) with an explicit residual-risk statement for threats that are not fully addressed
- [x] **SPEC-10**: Transport security requirements are specified: when TLS is required, when mTLS is required, and what happens when transport security is absent

### Phase 314: Native Protocol Conformance and Standards Track

- [x] **SPEC-11**: The conformance suite includes scenario categories for native ARC protocol behavior: capability validation, delegation chain attenuation, receipt integrity, and revocation propagation
- [x] **SPEC-12**: A third-party implementation can run the conformance suite against their kernel or agent and get a pass/fail report without depending on ARC Rust crates
- [x] **SPEC-13**: An IETF Internet-Draft is prepared that captures the normative protocol specification in standards-track format
- [x] **SPEC-14**: A standards alignment matrix maps ARC concepts to IETF/W3C/OpenID equivalents (GNAP, SCITT, RATS, RFC 9449, W3C VC, OID4VCI/VP, RFC 8785)

---

## v2.83 Coverage, Hardening, and Production Qualification

### Phase 315: Integration Test Coverage Expansion

- [x] **PROD-01**: Every crate under `crates/` has at least one integration test that exercises its public API against a realistic scenario (not just unit tests of internal functions)
- [x] **PROD-02**: Security-critical crates (arc-credentials, arc-policy, arc-store-sqlite) each have integration tests covering their primary success path, primary failure path, and at least one edge case
- [x] **PROD-03**: Integration tests for arc-a2a-adapter, arc-mcp-adapter, and arc-mcp-edge exercise the real protocol exchange, not just struct construction

### Phase 316: Coverage Push and Store Hardening

- [ ] **PROD-04**: Workspace code coverage measured by cargo-tarpaulin is at or above 80%, up from the current 67% baseline
- [ ] **PROD-05**: Coverage improvement is concentrated in the previously untested crates, not inflated by adding trivial tests to already well-covered code
- [ ] **PROD-06**: The SQLite receipt store uses connection pooling (r2d2, deadpool, or equivalent) or an async store trait so concurrent reads and writes do not serialize on a single connection

### Phase 317: Dead Code and API Surface Audit

- [ ] **PROD-07**: All `#[allow(dead_code)]` attributes in non-test code are resolved: the dead code is either removed or the attribute is justified with a comment explaining why the code must exist
- [ ] **PROD-08**: All 82 `#[allow(clippy::too_many_arguments)]` sites are refactored to accept config/builder/request structs instead of long parameter lists
- [ ] **PROD-09**: A `pub` visibility audit ensures no internal implementation types are exported from crate root modules unless they are part of the intended public API
- [ ] **PROD-10**: `cargo +nightly udeps` (or equivalent) confirms no unused dependencies remain in any workspace crate

### Phase 318: Structured Errors and Production Qualification

- [ ] **PROD-11**: CLI and kernel errors include a machine-readable error code, human-readable context, and a suggested fix or next step (e.g., "guard `forbidden_path` denied access to `/etc/passwd` -- add this path to your policy's `path_allowlist` or remove the `forbidden_path` guard")
- [ ] **PROD-12**: Error output supports both human-readable (default) and JSON-structured (via `--format json` flag) modes for programmatic consumption
- [ ] **PROD-13**: A production qualification bundle documents: test count, coverage percentage, benchmark baselines, conformance results, and known gaps for evaluators

---

## Traceability (v2.80-v2.83)

| Requirement | Phase | Status |
|-------------|-------|--------|
| DECOMP-01 | Phase 303 | Complete |
| DECOMP-02 | Phase 303 | Complete |
| DECOMP-03 | Phase 303 | Complete |
| DECOMP-04 | Phase 303 | Complete |
| DECOMP-05 | Phase 304 | Complete |
| DECOMP-06 | Phase 304 | Complete |
| DECOMP-07 | Phase 304 | Complete |
| DECOMP-08 | Phase 304 | Complete |
| DECOMP-09 | Phase 304 | Complete |
| ASYNC-01 | Phase 305 | Complete |
| ASYNC-02 | Phase 305 | Complete |
| ASYNC-03 | Phase 305 | Complete |
| ASYNC-04 | Phase 305 | Complete |
| DEPS-01 | Phase 306 | Complete |
| DEPS-02 | Phase 306 | Complete |
| DEPS-03 | Phase 306 | Complete |
| DEPS-04 | Phase 306 | Complete |
| ONBOARD-01 | Phase 307 | Complete |
| ONBOARD-02 | Phase 307 | Complete |
| ONBOARD-03 | Phase 307 | Complete |
| SDK-01 | Phase 308 | Complete |
| SDK-02 | Phase 308 | Complete |
| SDK-03 | Phase 308 | Complete |
| SDK-04 | Phase 308 | Complete |
| DEPLOY-01 | Phase 309 | Complete |
| DEPLOY-02 | Phase 309 | Complete |
| DEPLOY-03 | Phase 309 | Complete |
| TUTORIAL-01 | Phase 310 | Complete |
| TUTORIAL-02 | Phase 310 | Complete |
| TUTORIAL-03 | Phase 310 | Complete |
| TUTORIAL-04 | Phase 310 | Complete |
| SPEC-01 | Phase 311 | Complete |
| SPEC-02 | Phase 311 | Complete |
| SPEC-03 | Phase 311 | Complete |
| SPEC-04 | Phase 311 | Complete |
| SPEC-05 | Phase 312 | Complete |
| SPEC-06 | Phase 312 | Complete |
| SPEC-07 | Phase 312 | Complete |
| SPEC-08 | Phase 313 | Complete |
| SPEC-09 | Phase 313 | Complete |
| SPEC-10 | Phase 313 | Complete |
| SPEC-11 | Phase 314 | Complete |
| SPEC-12 | Phase 314 | Complete |
| SPEC-13 | Phase 314 | Complete |
| SPEC-14 | Phase 314 | Complete |
| PROD-01 | Phase 315 | Complete |
| PROD-02 | Phase 315 | Complete |
| PROD-03 | Phase 315 | Complete |
| PROD-04 | Phase 316 | Pending |
| PROD-05 | Phase 316 | Pending |
| PROD-06 | Phase 316 | Pending |
| PROD-07 | Phase 317 | Pending |
| PROD-08 | Phase 317 | Pending |
| PROD-09 | Phase 317 | Pending |
| PROD-10 | Phase 317 | Pending |
| PROD-11 | Phase 318 | Pending |
| PROD-12 | Phase 318 | Pending |
| PROD-13 | Phase 318 | Pending |

---

## v3.x Universal Security Kernel Requirements

### v3.0 Universal Security Kernel Foundation

#### Phase 319: arc-http-core Types and Request Model

- [ ] **CORE-01**: `arc-http-core` crate exists with `ArcHttpRequest`, `HttpMethod`, `CallerIdentity`, `AuthMethod`, and `SessionContext` types that represent any HTTP request ARC needs to evaluate
- [ ] **CORE-02**: `arc-http-core` defines `HttpReceipt` type that carries request_id, route_pattern, method, caller_identity_hash, session_id, verdict, guard_evidence, response_status, timestamp, content_hash, and Ed25519 signature
- [ ] **CORE-03**: `arc-http-core` defines `Verdict` enum (Allow, Deny, Cancel, Incomplete) consistent with existing ARC receipt decisions
- [ ] **CORE-04**: All `arc-http-core` types implement `Serialize`, `Deserialize`, and use canonical JSON (RFC 8785) for signed payloads

#### Phase 320: arc-openapi Parsing and Manifest Generation

- [ ] **CORE-05**: `arc-openapi` crate parses OpenAPI 3.0 and 3.1 specs (YAML and JSON) and extracts routes, methods, parameters, response schemas, and tags
- [ ] **CORE-06**: `arc-openapi` generates an ARC `ToolManifest` from a parsed OpenAPI spec where each route becomes a candidate `ToolDefinition` with input_schema derived from path/query/body params
- [ ] **CORE-07**: `arc-openapi` applies default policy: GET routes get session-scoped allow, POST/PUT/PATCH/DELETE routes require explicit capability grants (deny-by-default for side effects)
- [ ] **CORE-08**: `arc-openapi` supports `x-arc-*` extension fields (`x-arc-sensitivity`, `x-arc-side-effects`, `x-arc-approval-required`, `x-arc-budget-limit`, `x-arc-publish`) for per-route policy overrides
- [ ] **CORE-09**: Developer can run `arc-openapi` against a real OpenAPI spec (e.g., PetStore) and receive a valid ToolManifest with correct route coverage

#### Phase 321: arc.yaml Unified Configuration

- [ ] **CORE-10**: `arc-config` crate (or module) parses `arc.yaml` with kernel, adapters, edges, receipts, and logging sections using `serde::Deserialize` with `deny_unknown_fields`
- [ ] **CORE-11**: Environment variable interpolation (`${VAR}` and `${VAR:-default}`) resolves in all string-typed YAML fields before typed deserialization
- [ ] **CORE-12**: Validation rejects duplicate adapter IDs, broken edge `expose_from` references, missing required fields per protocol, and incomplete auth blocks at parse time with clear error messages
- [ ] **CORE-13**: A minimal valid `arc.yaml` requires only the kernel section and at least one adapter entry; all other sections default to sensible values

#### Phase 322: arc api protect CLI

- [ ] **CORE-14**: Developer can run `arc api protect --upstream http://localhost:8000 --spec openapi.yaml` and ARC starts a reverse proxy that intercepts all requests
- [ ] **CORE-15**: The reverse proxy reads the OpenAPI spec, generates a default manifest and policy, and applies deny-by-default for side-effect routes without a capability token
- [ ] **CORE-16**: Every proxied request produces a signed `HttpReceipt` stored in the local SQLite receipt store
- [ ] **CORE-17**: `arc api protect` auto-discovers the OpenAPI spec from `/openapi.json` or a file path when `--spec` is omitted
- [ ] **CORE-18**: GET requests pass through with session-scoped audit receipts; POST/PUT/DELETE requests without a capability token receive a structured 403 response with error code and suggested fix

### v3.1 Attestation Completion

#### Phase 323: ReceiptSigner and CapabilityChecker Traits

- [ ] **ATT-01**: `ReceiptSigner` trait is defined in `arc-acp-proxy` with `sign_acp_receipt(&self, request: &AcpReceiptRequest) -> Result<ArcReceipt, ReceiptSignError>` signature
- [ ] **ATT-02**: `CapabilityChecker` trait is defined in `arc-acp-proxy` with `check_access(&self, request: &AcpCapabilityRequest) -> Result<AcpVerdict, CapabilityCheckError>` signature
- [ ] **ATT-03**: Both traits are `Option`-wrapped in `MessageInterceptor` so standalone proxy mode (unsigned) remains available but is explicitly labeled as outside full attestation claims
- [ ] **ATT-04**: `AcpProxy::start_with_kernel` constructor accepts injected signer and checker; `AcpProxy::start` remains unchanged for standalone mode

#### Phase 324: ACP Kernel Integration

- [ ] **ATT-05**: Kernel-backed `ReceiptSigner` implementation signs ACP tool-call events into `ArcReceipt` objects with Ed25519 signatures, capability_id, policy_hash, and content_hash
- [ ] **ATT-06**: Kernel-backed `CapabilityChecker` implementation validates session capability tokens for file read, file write, and terminal execute operations with fail-closed semantics
- [ ] **ATT-07**: Signed ACP receipts are appended to the kernel's `ReceiptStore` and included in Merkle checkpoint batches alongside MCP and A2A receipts
- [ ] **ATT-08**: `AcpAttestationMode::Required` causes signer failure to produce an explicit attestation-gap artifact and mark the session non-compliant; unsigned events are only permitted in `UnsignedCompatibility` mode

#### Phase 325: Session Compliance Certificate

- [ ] **ATT-09**: `generate_compliance_certificate(session_id)` walks the complete receipt log for a session, verifying signatures, chain continuity, scope containment, budget compliance, guard passage, and delegation monotonicity
- [ ] **ATT-10**: Any anomaly during certificate generation aborts with a typed error (EmptySession, InvalidReceiptSignature, ChainDiscontinuity, ScopeViolation, BudgetExceeded, GuardBypass) rather than issuing a misleading certificate
- [ ] **ATT-11**: Certificate verification API supports lightweight mode (trusts kernel assertions) and full-bundle mode (independently reconstructs Merkle root from receipt bundle)
- [ ] **ATT-12**: `arc cert generate --session <id>`, `arc cert verify --cert <path>`, and `arc cert inspect --cert <path>` CLI commands work end-to-end

#### Phase 326: OpenTelemetry Export

- [ ] **ATT-13**: Receipt data exports as OpenTelemetry spans with trace_id, span_id, tool_name, verdict, duration, and capability_id attributes
- [ ] **ATT-14**: OTel export is configurable in `arc.yaml` under a `telemetry` or `exporters` section with endpoint URL and protocol (gRPC or HTTP)
- [ ] **ATT-15**: Compliance certificate events export as OTel span events attached to the session's root span

### v3.2 Python Adoption

#### Phase 327: arc-sdk-python Core

- [ ] **PY-01**: `arc-sdk-python` Python package provides a thin HTTP client that communicates with the ARC sidecar and exposes typed Python classes for `CapabilityToken`, `ArcReceipt`, `GuardEvidence`, and `Verdict`
- [ ] **PY-02**: Python SDK supports creating, validating, and attenuating capability tokens from Python code
- [ ] **PY-03**: Python SDK supports verifying receipt signatures and chain continuity from Python code
- [ ] **PY-04**: Package installs via `pip install arc-sdk-python` with pre-built wheels for Linux x86_64, macOS arm64, and macOS x86_64

#### Phase 328: arc-asgi Middleware

- [ ] **PY-05**: `arc-asgi` ASGI middleware intercepts requests, extracts caller identity (JWT, session cookie, API key), evaluates capabilities, runs guards, and signs receipts
- [ ] **PY-06**: `arc-asgi` middleware integrates with any ASGI-compliant framework (FastAPI, Starlette, Litestar) via standard `app.add_middleware()` pattern
- [ ] **PY-07**: `arc-asgi` middleware produces signed `HttpReceipt` objects for every request, stored in the configured receipt store

#### Phase 329: arc-fastapi and arc-django Wrappers

- [ ] **PY-08**: `arc-fastapi` provides `@arc_requires(scope=...)`, `@arc_approval(reason=...)`, and `@arc_budget(calls=..., cost_usd=...)` decorators for per-route ARC policy
- [ ] **PY-09**: `arc-django` middleware works with Django WSGI and Django REST Framework, extracting identity from Django's auth system and producing receipts
- [ ] **PY-10**: Both wrappers return framework-native error responses (FastAPI JSONResponse, Django HttpResponse) with ARC error codes and suggested fixes

#### Phase 330: arc-langchain Integration and Conformance

- [ ] **PY-11**: `arc-langchain` wraps ARC-governed tools as LangChain `Tool` objects so agents using LangChain invoke tools through ARC's capability and guard pipeline
- [ ] **PY-12**: Conformance tests validate that the Python SDK's capability validation, receipt signing, and guard evaluation produce byte-identical results to the Rust kernel for a shared test vector set
- [ ] **PY-13**: End-to-end test demonstrates a FastAPI app protected by `arc-fastapi` producing signed receipts that pass `arc cert verify`

### v3.3 TypeScript Adoption

#### Phase 331: @arc-protocol/node-http Substrate

- [ ] **TS-01**: `@arc-protocol/node-http` npm package provides the common HTTP interception substrate handling `(req, res)` and `Request -> Response` patterns for Node and Bun runtimes
- [ ] **TS-02**: Substrate extracts caller identity from Authorization headers, cookies, and API key headers with configurable extraction strategies
- [ ] **TS-03**: Substrate evaluates capabilities, runs guards, and produces signed receipts for every request by calling the ARC sidecar over localhost HTTP

#### Phase 332: Express and Fastify Wrappers

- [ ] **TS-04**: `@arc-protocol/express` provides `app.use(arc({ config: 'arc.yaml' }))` middleware for Express apps
- [ ] **TS-05**: `@arc-protocol/fastify` provides a Fastify plugin with `fastify.register(arc, { config: 'arc.yaml' })` integration
- [ ] **TS-06**: Both wrappers return framework-native error responses with ARC error codes, suggested fixes, and proper HTTP status codes

#### Phase 333: Elysia Wrapper and npm Packaging

- [ ] **TS-07**: `@arc-protocol/elysia` provides an Elysia lifecycle hook via `.use(arc({ config: 'arc.yaml' }))` integration
- [ ] **TS-08**: All four npm packages (`node-http`, `express`, `fastify`, `elysia`) publish with TypeScript type definitions and pass `tsc --strict` type checking
- [ ] **TS-09**: Packages support both ESM and CommonJS module systems

#### Phase 334: TypeScript Conformance

- [ ] **TS-10**: Conformance tests validate that the TypeScript SDK's capability validation and receipt signing produce byte-identical results to the Rust kernel for a shared test vector set
- [ ] **TS-11**: End-to-end test demonstrates an Express app protected by `@arc-protocol/express` producing signed receipts that pass `arc cert verify`
- [ ] **TS-12**: End-to-end test demonstrates a Fastify app protected by `@arc-protocol/fastify` producing signed receipts that pass `arc cert verify`

### v3.4 Guard Expansion

#### Phase 335: Session Journal

- [ ] **GUARD-01**: `arc-http-session` crate (or module) maintains a per-session journal tracking request history, cumulative data flow (bytes read/written), delegation depth, and tool invocation sequence
- [ ] **GUARD-02**: Session journal persists across requests within a session and is available to all guards in the evaluation pipeline
- [ ] **GUARD-03**: Session journal entries are append-only and hash-chained for tamper detection

#### Phase 336: Stateless Deterministic Guards

- [ ] **GUARD-04**: `InternalNetworkGuard` denies requests targeting RFC 1918, loopback, link-local, or cloud metadata addresses (SSRF prevention) with configurable allowlist
- [ ] **GUARD-05**: `AgentVelocityGuard` enforces per-agent and per-session rate limits with configurable windows and thresholds

#### Phase 337: Session-Aware Deterministic Guards

- [ ] **GUARD-06**: `DataFlowGuard` enforces cumulative bytes-read and bytes-written limits per session using the session journal, denying when thresholds are exceeded
- [ ] **GUARD-07**: All new deterministic guards produce `GuardEvidence` entries with verdict, guard name, and evaluation context; all fail closed on errors

- [ ] **GUARD-08**: Post-invocation hook pipeline inspects tool responses after execution but before delivery to the caller, with the ability to block, redact, or escalate
- [ ] **GUARD-09**: `ResponseSanitizationGuard` scans response bodies for PII/PHI patterns and redacts or blocks based on data classification policy
- [ ] **GUARD-10**: `BehavioralSequenceGuard` evaluates tool invocation order against a declared sequence policy (e.g., "read before write", "approve before deploy") using the session journal

#### Phase 338: Advisory Signals

- [ ] **GUARD-11**: Advisory signal framework emits signed, non-blocking evidence observations (drift detection, unusual data-volume spikes, cross-tool exfiltration pattern hints) attached to receipts
- [ ] **GUARD-12**: Advisory signals are clearly distinguished from deterministic guard verdicts in receipt evidence -- they never block requests unless explicitly promoted to deterministic guards by operator configuration
- [ ] **GUARD-13**: Operator can promote an advisory signal to a deterministic guard via `arc.yaml` configuration without code changes

### v3.5 Protocol Breadth

#### Phase 339: MCP Adapter Completion

- [ ] **PROTO-01**: MCP adapter test count reaches 80+, up from 14, covering streaming responses, error propagation, resource template resolution, nested flows, and OAuth token refresh
- [ ] **PROTO-02**: MCP adapter handles partial/chunked tool output with proper receipt generation for each chunk
- [ ] **PROTO-03**: MCP adapter error paths produce structured denial receipts with error codes matching the ARC error taxonomy

#### Phase 340: OpenAPI-to-MCP Bridge

- [ ] **PROTO-04**: An ARC-governed HTTP API (protected by `arc api protect` or framework middleware) can appear as an MCP tool surface so MCP-speaking agents can discover and invoke its routes
- [ ] **PROTO-05**: The bridge generates MCP `tools/list` entries from the API's OpenAPI spec with correct input schemas derived from path, query, and body parameters
- [ ] **PROTO-06**: Bridge invocations flow through the ARC kernel with full capability validation, guard evaluation, and receipt signing

#### Phase 341: A2A and ACP Edge Crates

- [ ] **PROTO-07**: `arc-a2a-edge` crate exposes ARC-native tools as A2A Agent Card skills, handling `SendMessage` (blocking) and `SendStreamingMessage` (SSE) with kernel-mediated receipts
- [ ] **PROTO-08**: `arc-a2a-edge` generates a valid A2A Agent Card at `/.well-known/agent-card.json` from loaded tool manifests
- [ ] **PROTO-09**: `arc-acp-edge` crate exposes ARC-native tools as ACP capabilities with `session/prompt` invocation, `session/request_permission` backed by ARC capabilities, and stdio transport
- [ ] **PROTO-10**: Both edge crates evaluate `BridgeFidelity` per tool and suppress publication for tools with `Unsupported` fidelity

#### Phase 342: arc-openai Adapter

- [ ] **PROTO-11**: `arc-openai` adapter intercepts OpenAI-style `tool_use` / function-calling requests and routes them through the ARC kernel
- [ ] **PROTO-12**: Adapter produces signed receipts for every function call, with the OpenAI function name as tool_name and arguments as the receipt's parameter content
- [ ] **PROTO-13**: Adapter supports both the Chat Completions API function-calling format and the Responses API tool_use format

### v3.6 Platform Extensions

#### Phase 343: Go SDK and net/http Middleware

- [ ] **PLAT-01**: `arc-go-http` Go module provides `arc.Protect(handler, arc.ConfigFile("arc.yaml"))` that wraps any `http.Handler` with ARC capability validation, guard evaluation, and receipt signing
- [ ] **PLAT-02**: Go middleware extracts caller identity from Authorization headers, cookies, and API key headers with configurable strategies
- [ ] **PLAT-03**: Go middleware produces signed `HttpReceipt` objects stored in the configured receipt store
- [ ] **PLAT-04**: Conformance tests validate Go SDK behavior against Rust kernel for shared test vectors

#### Phase 344: Kubernetes Controller and Injector

- [ ] **PLAT-05**: `arc-k8s-admission` admission controller rejects pod deployments that lack a valid ARC capability token annotation or label
- [ ] **PLAT-06**: `arc-k8s-injector` mutating webhook automatically injects `arc api protect` as a sidecar container for annotated deployments
- [ ] **PLAT-07**: Operator can configure admission policies via a `ArcPolicy` CRD specifying required capability scopes per namespace or deployment label
- [ ] **PLAT-08**: Sidecar injector configures the proxy's upstream URL, OpenAPI spec path, and receipt store from pod annotations

#### Phase 345: arc-tower Rust Middleware

- [ ] **PLAT-09**: `arc-tower` crate implements `tower::Layer` that wraps any `tower::Service` with ARC capability validation, guard evaluation, and receipt signing
- [ ] **PLAT-10**: Axum integration test demonstrates `arc-tower` as a middleware layer producing signed receipts for every request
- [ ] **PLAT-11**: Tonic (gRPC) integration test demonstrates `arc-tower` producing signed receipts for gRPC service calls

#### Phase 346: JVM and .NET Substrates

- [ ] **PLAT-12**: `arc-jvm` provides a Servlet filter and/or Spring Boot auto-configuration that wraps HTTP requests with ARC capability validation and receipt signing
- [ ] **PLAT-13**: `arc-dotnet` provides ASP.NET Core middleware that wraps HTTP requests with ARC capability validation and receipt signing
- [ ] **PLAT-14**: Both substrates communicate with the Rust kernel via sidecar HTTP (primary model), with FFI or embedded WASM as optional optimization paths
- [ ] **PLAT-15**: Conformance tests validate JVM and .NET SDK behavior against Rust kernel for shared test vectors

### v3.7 Strategic Bets

#### Phase 347: WASM Guard Runtime

- [ ] **STRAT-01**: WASM guard runtime loads custom guards compiled to WASM (`.wasm` files) and executes them in a sandboxed runtime with deterministic fuel metering
- [ ] **STRAT-02**: Guard WASM API provides the guard with read-only access to `ArcHttpRequest`, `SessionContext`, and `GuardConfig`, and expects a `GuardVerdict` return value
- [ ] **STRAT-03**: WASM guards have bounded execution time (configurable fuel limit) and bounded memory (configurable page limit) with fail-closed behavior on resource exhaustion
- [ ] **STRAT-04**: Developer can author a custom guard in Rust, AssemblyScript, or Go, compile to WASM, and load it via `arc.yaml` guard configuration

#### Phase 348: Receipt Metering and Economics

- [ ] **STRAT-05**: Receipt metering surface attaches per-receipt cost attribution (compute time, data volume, external API cost) as structured metadata
- [ ] **STRAT-06**: Operator can query cumulative cost by session, agent, tool, or time range via `arc receipts cost` CLI and programmatic API
- [ ] **STRAT-07**: Monetary budget enforcement per grant uses denominated currency (via arc-link oracle) with fail-closed deny when the budget is exhausted
- [ ] **STRAT-08**: Receipt cost metadata is compatible with billing export for managed service scenarios

#### Phase 349: AG-UI Proxy

- [ ] **STRAT-09**: `arc-ag-ui-proxy` intercepts Agent-to-UI event streams, validates capability tokens for UI-facing actions, and signs receipts for every delivered event
- [ ] **STRAT-10**: Proxy supports SSE and WebSocket transport modes for agent-to-UI event delivery
- [ ] **STRAT-11**: UI-facing receipts include event type, target component, and action classification for audit trail

#### Phase 350: Skill and Workflow Authority

- [ ] **STRAT-12**: `SkillGrant` type extends the capability model to represent multi-step skill composition with ordered tool sequences and intermediate checkpoints
- [ ] **STRAT-13**: `SkillManifest` type describes a composed skill's tool dependencies, input/output contracts, and budget envelope
- [ ] **STRAT-14**: `WorkflowReceipt` type captures the complete execution trace of a multi-step workflow as a single auditable artifact with per-step receipts and an aggregate verdict
- [ ] **STRAT-15**: Workflow authority validates that each step in a composed skill operates within its declared scope and budget, denying execution when any step would violate the workflow's envelope

### v3.8 Normative Specification Alignment

#### Phase 351: HTTP Substrate Specification

- [ ] **SPEC-01**: `spec/HTTP-SUBSTRATE.md` defines the sidecar evaluation protocol endpoints (`POST /arc/evaluate`, `POST /arc/verify`, `GET /arc/health`) with JSON request/response schemas
- [ ] **SPEC-02**: `spec/HTTP-SUBSTRATE.md` defines the `HttpReceipt` type normatively with all fields matching the `arc-http-core` crate implementation
- [ ] **SPEC-03**: `spec/HTTP-SUBSTRATE.md` defines `ArcHttpRequest`, `CallerIdentity`, `AuthMethod` (bearer, api_key, cookie, mtls_certificate, anonymous), `SessionContext`, and `Verdict` (with http_status) types
- [ ] **SPEC-04**: `spec/HTTP-SUBSTRATE.md` documents the `HttpReceipt` to `ArcReceipt` mapping including the known signature limitation
- [ ] **SPEC-05**: `spec/schemas/arc-http/v1/` contains JSON Schema documents for HttpReceipt, ArcHttpRequest, CallerIdentity, Verdict, and the sidecar evaluate request/response

#### Phase 352: OpenAPI Integration Specification

- [ ] **SPEC-06**: `spec/OPENAPI-INTEGRATION.md` defines the OpenAPI 3.0/3.1 to ARC manifest pipeline with parsing rules and ToolDefinition derivation from path, query, and body parameters
- [ ] **SPEC-07**: `spec/OPENAPI-INTEGRATION.md` defines the `x-arc-*` extension vocabulary (`x-arc-sensitivity`, `x-arc-side-effects`, `x-arc-approval-required`, `x-arc-budget-limit`, `x-arc-publish`) with allowed values and policy effects
- [ ] **SPEC-08**: `spec/OPENAPI-INTEGRATION.md` defines the default deny-by-method policy: safe methods (GET/HEAD/OPTIONS) get session-scoped allow, side-effect methods (POST/PUT/PATCH/DELETE) require explicit capability
- [ ] **SPEC-09**: `spec/OPENAPI-INTEGRATION.md` defines the `arc api protect` reverse proxy contract including command-line flags, auto-discovery behavior, structured 403 response schema, and receipt storage

#### Phase 353: PROTOCOL.md v3 Addendum

- [ ] **SPEC-10**: `spec/PROTOCOL.md` version bumped to 3.0 with clear v2 and v3 scope boundaries
- [ ] **SPEC-11**: Receipt contract section references `HttpReceipt` alongside `ArcReceipt` with explicit type relationship and conversion semantics
- [ ] **SPEC-12**: Manifest contract section references OpenAPI-derived manifests and the `x-arc-*` extension vocabulary alongside `arc.manifest.v1`
- [ ] **SPEC-13**: Runtime surfaces section adds `arc api protect` and `arc cert generate/verify/inspect` CLI entrypoints

#### Phase 354: Guard Taxonomy and Security Model Update

- [ ] **SPEC-14**: `spec/GUARDS.md` defines the full guard taxonomy: stateless deterministic, session-aware deterministic, post-invocation hooks, advisory signals, and WASM custom guards with their evaluation semantics
- [ ] **SPEC-15**: `spec/GUARDS.md` defines the advisory signal framework including severity levels, signed evidence, non-blocking semantics, and operator-configurable promotion via arc.yaml
- [ ] **SPEC-16**: `spec/SECURITY.md` threat register extended with HTTP-specific threats: SSRF, PII/PHI exposure, velocity abuse, data exfiltration, and behavioral sequence attacks, each mapped to the guard that mitigates it
- [ ] **SPEC-17**: `spec/GUARDS.md` defines the session journal contract: append-only hash-chained entries, cumulative data-flow accounting, delegation depth tracking, and availability to all guards in the pipeline

#### Phase 355: Configuration and Compliance Specification

- [ ] **SPEC-18**: `spec/CONFIGURATION.md` defines the arc.yaml schema normatively with all sections (kernel, adapters, edges, receipts, logging, telemetry, guards, wasm_guards), validation rules, env var interpolation syntax, and minimal valid config requirements
- [ ] **SPEC-19**: `spec/COMPLIANCE-CERTIFICATE.md` defines the certificate format, six typed abort errors, lightweight and full-bundle verification modes, and `arc cert` CLI interface
- [ ] **SPEC-20**: `spec/METERING.md` defines cost attribution metadata (CostDimension, CostMetadata), budget enforcement semantics, billing export format, and `arc receipts cost` query interface
- [ ] **SPEC-21**: `spec/WORKFLOW.md` defines SkillGrant, SkillManifest, WorkflowReceipt types, step ordering semantics, budget envelope enforcement, and the WorkflowAuthority lifecycle (begin, validate_step, record_step, finalize)
- [ ] **SPEC-22**: Design docs (`UNIFIED-CONFIGURATION.md`, `SESSION-COMPLIANCE-CERTIFICATE.md`) updated to reference normative specs and reclassified as design rationale

#### Phase 356: SDK Reference Documentation

- [ ] **SPEC-23**: `docs/sdk/PYTHON.md` documents all five Python packages (arc-sdk-python, arc-asgi, arc-fastapi, arc-django, arc-langchain) with public API, usage examples, and sidecar model description
- [ ] **SPEC-24**: `docs/sdk/TYPESCRIPT.md` documents all five TypeScript packages (@arc-protocol/node-http, express, fastify, elysia, conformance) with public API, usage examples, and sidecar model description
- [ ] **SPEC-25**: `docs/sdk/GO.md` documents arc-go-http middleware with public API, usage examples, and sidecar model description
- [ ] **SPEC-26**: All SDK docs explicitly state the sidecar communication model: SDKs communicate with the ARC Rust kernel via localhost HTTP at default 127.0.0.1:9090, configurable via ARC_SIDECAR_URL

#### Phase 357: Protocol Bridge and Edge Documentation

- [ ] **SPEC-27**: `spec/BRIDGES.md` defines the OpenAPI-to-MCP bridge: how HTTP APIs appear as MCP tools, tools/list generation from OpenAPI specs, invocation flow through the kernel
- [ ] **SPEC-28**: `spec/BRIDGES.md` defines the A2A edge: Agent Card generation at /.well-known/agent-card.json, SendMessage and streaming support, BridgeFidelity evaluation and tool suppression semantics
- [ ] **SPEC-29**: `spec/BRIDGES.md` defines the ACP edge: capability mapping, permission evaluation, category inference, BridgeFidelity assessment
- [ ] **SPEC-30**: `spec/BRIDGES.md` defines the OpenAI adapter: function-calling interception, receipt generation, Chat Completions and Responses API format support

#### Phase 358: Strategic Vision and Design Doc Reconciliation

- [x] **SPEC-31**: `docs/protocols/STRATEGIC-VISION.md` updated with shipped status for all Tier 1/2/3 items and new future-horizon section
- [x] **SPEC-32**: `docs/protocols/HTTP-FRAMEWORK-INTEGRATION-STRATEGY.md` updated with shipped status for all 6 build phases, actual crate/package names, and implementation notes
- [x] **SPEC-33**: `docs/sdk/PLATFORM.md` documents arc-tower (Rust), K8s controller/injector, JVM Spring Boot, and .NET ASP.NET Core substrates with usage examples
- [x] **SPEC-34**: `spec/WIRE_PROTOCOL.md` updated with Section 7 referencing the HTTP substrate as a fourth cooperating protocol surface

---

Historical note: the phase-local checkbox lists above preserve the original
planning documents. For `v3.0` through `v3.8`, the authoritative reconciled
state is now the traceability table below, which marks those phases as
implemented but still awaiting a dedicated audit closeout rather than flat
`Planned`. For `v3.9` through `v3.11`, the traceability table reflects the
reconciled execution truth from the remediation lane even where the original
checklists were never flipped at the time.

### v3.9 Runtime Correctness and Contract Remediation

#### Phase 359: OpenAI Adapter Kernel Execution

- [ ] **REM-01**: `arc-openai` routes OpenAI function calls through `ArcKernel::evaluate_tool_call_blocking` using a real `ToolCallRequest` rather than calling a tool server directly
- [ ] **REM-02**: `ToolCallResult` carries the kernel-signed `ArcReceipt` object for calls that reach the kernel and uses the receipt's real `id` as `receipt_ref`
- [ ] **REM-03**: OpenAI adapter tests cover allow, deny, tool-server error, unknown function, and argument-parse failure under the kernel-backed execution path

#### Phase 360: Compliance Certificate Wire Format Alignment

- [ ] **REM-04**: Compliance certificate JSON serializes with snake_case field names matching `spec/COMPLIANCE-CERTIFICATE.md` (`session_id`, `receipt_count`, `signer_key`, `receipts_reverified`, etc.)
- [ ] **REM-05**: `arc cert generate`, `arc cert verify`, and `arc cert inspect` continue to work with the corrected wire format and accept previously emitted camelCase payloads when feasible

#### Phase 361: HTTP Adapter Request Binding and Capability Validation

- [x] **REM-06**: `arc-api-protect` and `arc-tower` parse query parameters into the normalized `ArcHttpRequest` so query values participate in the receipt `content_hash`
- [x] **REM-07**: `arc-api-protect` and `arc-tower` carry `capability_id` into `ArcHttpRequest` and `HttpReceipt` when a valid capability token is presented in `X-Arc-Capability` or `arc_capability`
- [x] **REM-08**: Unsafe HTTP requests with malformed, invalid-signature, or expired capability tokens are denied fail-closed instead of being allowed on token presence alone

#### Phase 362: Test Stabilization and Invariant Enforcement

- [ ] **REM-09**: `crates/arc-cli/tests/mcp_serve.rs` no longer exhibits order-sensitive flake under repeated or concurrent workspace test execution
- [ ] **REM-10**: Workspace-level lint configuration documents and enforces the no-`unwrap`/`expect` invariant at the root in addition to crate-local clippy settings

#### Phase 363: Residual SDK and Spec Drift Cleanup

- [ ] **REM-11**: `spec/CONFIGURATION.md` no longer documents a nonexistent `arc start --config arc.yaml` command as the normative configuration entrypoint
- [ ] **REM-12**: Python SDK, ASGI, and Django timeout defaults are `5.0` seconds (5000ms) to match `spec/HTTP-SUBSTRATE.md`
- [x] **REM-13**: Documentation is updated anywhere the runtime contract changed during remediation, including OpenAI receipt behavior and capability-token validation semantics

---

### v3.10 HTTP Sidecar and Cross-SDK Contract Completion

#### Phase 364: Rust HTTP Sidecar Surface

- [ ] **ALIGN-01**: `arc-api-protect` exposes `POST /arc/evaluate` and returns a normative `EvaluateResponse` with `200 OK` for both allow and deny verdicts
- [ ] **ALIGN-02**: `arc-api-protect` exposes `POST /arc/verify` for `HttpReceipt` signature verification and `GET /arc/health` with the normative `status` and `version` fields
- [ ] **ALIGN-03**: The in-repo Rust sidecar implementation stores signed receipts from `/arc/evaluate` and uses the same kernel/evaluator path as the proxy runtime

#### Phase 365: Python HTTP Substrate Alignment

- [ ] **ALIGN-04**: `arc-sdk-python` uses `/arc/health`, `/arc/verify`, and `/arc/evaluate` for the HTTP substrate instead of the pre-v3 `/health` and `/v1/evaluate-http` surface
- [ ] **ALIGN-05**: `arc-sdk-python` publishes `ArcHttpRequest` and `EvaluateResponse` typed models, and `evaluate_http_request()` returns `EvaluateResponse`
- [ ] **ALIGN-06**: `arc-asgi`, `arc-django`, and `arc-fastapi` consume the normative sidecar response shape and do not rely on `403` deny responses from the sidecar

#### Phase 366: Cross-SDK Capability Presentation Alignment

- [x] **ALIGN-07**: TypeScript, Go, JVM, and .NET HTTP adapters stop forwarding raw capability-token material inside `ArcHttpRequest.headers`
- [x] **ALIGN-08**: TypeScript, Go, JVM, and .NET carry the presented token's `id` in `capability_id` when derivable and preserve both header and query-param presentation paths in user-facing deny guidance
- [x] **ALIGN-09**: Platform SDK docs (`docs/sdk/PLATFORM.md` and per-language references where relevant) describe header-or-query capability presentation semantics consistently with the normative spec

#### Phase 367: HTTP Receipt Conversion Safety

- [ ] **ALIGN-10**: `HttpReceipt::to_arc_receipt()` no longer returns an `ArcReceipt` with a copied invalid signature, and the crate offers only explicit fail-closed or re-signing-based conversion behavior

---

### v3.11 Sidecar Entrypoint and Body-Integrity Completion

#### Phase 368: Shippable `arc api protect` Entrypoint

- [ ] **FINAL-01**: `arc` exposes an `api protect` subcommand that launches the HTTP sidecar runtime documented in `spec/OPENAPI-INTEGRATION.md`
- [ ] **FINAL-02**: The `api protect` command accepts `--upstream`, optional `--spec`, and optional `--listen`, and loads or auto-discovers the OpenAPI spec instead of requiring preloaded `spec_content`
- [ ] **FINAL-03**: The Kubernetes injector's documented sidecar command line is runnable against the checked-in CLI without local patching or hidden entrypoints

#### Phase 369: TypeScript Request-Body Preservation

- [ ] **FINAL-04**: `@arc-protocol/node-http` preserves request bodies for downstream consumers when computing body hashes for Node and Web request interception
- [ ] **FINAL-05**: `@arc-protocol/express` remains body-safe for downstream handlers on body-bearing requests, and TypeScript docs no longer recommend direct interception patterns that drain bodies irreversibly

#### Phase 370: JVM Request-Body Preservation and Raw-Byte Hashing

- [ ] **FINAL-06**: `arc-spring-boot` wraps requests so downstream filters and controllers can still read the body after ARC evaluation
- [ ] **FINAL-07**: JVM request hashing is computed from the raw request bytes, not UTF-8-decoded strings

#### Phase 371: Cross-SDK Raw-Byte Binding and EvaluateResponse Contract

- [x] **FINAL-08**: Fastify and .NET compute `body_hash` from raw request bytes rather than reparsed JSON or decoded strings
- [ ] **FINAL-09**: `EvaluateResponse.evidence` is always serialized on the wire so the Rust runtime matches `spec/HTTP-SUBSTRATE.md` and the shipped JSON schema

#### Phase 372: HTTP Schema and Platform Doc Consistency

- [x] **FINAL-10**: The HTTP JSON schemas model nullable optional fields (`body_hash`, `session_id`, `capability_id`) consistently with the prose spec and Rust `Option<_>` types
- [x] **FINAL-11**: `docs/sdk/PLATFORM.md` consistently documents capability transport as `X-Arc-Capability` header or `arc_capability` query parameter everywhere

---

## Traceability (v3.0-v3.11)

| Requirement | Phase | Status |
|-------------|-------|--------|
| CORE-01 | Phase 319 | Implemented / audit pending |
| CORE-02 | Phase 319 | Implemented / audit pending |
| CORE-03 | Phase 319 | Implemented / audit pending |
| CORE-04 | Phase 319 | Implemented / audit pending |
| CORE-05 | Phase 320 | Implemented / audit pending |
| CORE-06 | Phase 320 | Implemented / audit pending |
| CORE-07 | Phase 320 | Implemented / audit pending |
| CORE-08 | Phase 320 | Implemented / audit pending |
| CORE-09 | Phase 320 | Implemented / audit pending |
| CORE-10 | Phase 321 | Implemented / audit pending |
| CORE-11 | Phase 321 | Implemented / audit pending |
| CORE-12 | Phase 321 | Implemented / audit pending |
| CORE-13 | Phase 321 | Implemented / audit pending |
| CORE-14 | Phase 322 | Implemented / audit pending |
| CORE-15 | Phase 322 | Implemented / audit pending |
| CORE-16 | Phase 322 | Implemented / audit pending |
| CORE-17 | Phase 322 | Implemented / audit pending |
| CORE-18 | Phase 322 | Implemented / audit pending |
| ATT-01 | Phase 323 | Implemented / audit pending |
| ATT-02 | Phase 323 | Implemented / audit pending |
| ATT-03 | Phase 323 | Implemented / audit pending |
| ATT-04 | Phase 323 | Implemented / audit pending |
| ATT-05 | Phase 324 | Implemented / audit pending |
| ATT-06 | Phase 324 | Implemented / audit pending |
| ATT-07 | Phase 324 | Implemented / audit pending |
| ATT-08 | Phase 324 | Implemented / audit pending |
| ATT-09 | Phase 325 | Implemented / audit pending |
| ATT-10 | Phase 325 | Implemented / audit pending |
| ATT-11 | Phase 325 | Implemented / audit pending |
| ATT-12 | Phase 325 | Implemented / audit pending |
| ATT-13 | Phase 326 | Implemented / audit pending |
| ATT-14 | Phase 326 | Implemented / audit pending |
| ATT-15 | Phase 326 | Implemented / audit pending |
| PY-01 | Phase 327 | Implemented / audit pending |
| PY-02 | Phase 327 | Implemented / audit pending |
| PY-03 | Phase 327 | Implemented / audit pending |
| PY-04 | Phase 327 | Implemented / audit pending |
| PY-05 | Phase 328 | Implemented / audit pending |
| PY-06 | Phase 328 | Implemented / audit pending |
| PY-07 | Phase 328 | Implemented / audit pending |
| PY-08 | Phase 329 | Implemented / audit pending |
| PY-09 | Phase 329 | Implemented / audit pending |
| PY-10 | Phase 329 | Implemented / audit pending |
| PY-11 | Phase 330 | Implemented / audit pending |
| PY-12 | Phase 330 | Implemented / audit pending |
| PY-13 | Phase 330 | Implemented / audit pending |
| TS-01 | Phase 331 | Implemented / audit pending |
| TS-02 | Phase 331 | Implemented / audit pending |
| TS-03 | Phase 331 | Implemented / audit pending |
| TS-04 | Phase 332 | Implemented / audit pending |
| TS-05 | Phase 332 | Implemented / audit pending |
| TS-06 | Phase 332 | Implemented / audit pending |
| TS-07 | Phase 333 | Implemented / audit pending |
| TS-08 | Phase 333 | Implemented / audit pending |
| TS-09 | Phase 333 | Implemented / audit pending |
| TS-10 | Phase 334 | Implemented / audit pending |
| TS-11 | Phase 334 | Implemented / audit pending |
| TS-12 | Phase 334 | Implemented / audit pending |
| GUARD-01 | Phase 335 | Implemented / audit pending |
| GUARD-02 | Phase 335 | Implemented / audit pending |
| GUARD-03 | Phase 335 | Implemented / audit pending |
| GUARD-04 | Phase 336 | Implemented / audit pending |
| GUARD-05 | Phase 336 | Implemented / audit pending |
| GUARD-06 | Phase 337 | Implemented / audit pending |
| GUARD-07 | Phase 336 | Implemented / audit pending |
| GUARD-08 | Phase 337 | Implemented / audit pending |
| GUARD-09 | Phase 337 | Implemented / audit pending |
| GUARD-10 | Phase 337 | Implemented / audit pending |
| GUARD-11 | Phase 338 | Implemented / audit pending |
| GUARD-12 | Phase 338 | Implemented / audit pending |
| GUARD-13 | Phase 338 | Implemented / audit pending |
| PROTO-01 | Phase 339 | Implemented / audit pending |
| PROTO-02 | Phase 339 | Implemented / audit pending |
| PROTO-03 | Phase 339 | Implemented / audit pending |
| PROTO-04 | Phase 340 | Implemented / audit pending |
| PROTO-05 | Phase 340 | Implemented / audit pending |
| PROTO-06 | Phase 340 | Implemented / audit pending |
| PROTO-07 | Phase 341 | Implemented / audit pending |
| PROTO-08 | Phase 341 | Implemented / audit pending |
| PROTO-09 | Phase 341 | Implemented / audit pending |
| PROTO-10 | Phase 341 | Implemented / audit pending |
| PROTO-11 | Phase 342 | Implemented / audit pending |
| PROTO-12 | Phase 342 | Implemented / audit pending |
| PROTO-13 | Phase 342 | Implemented / audit pending |
| PLAT-01 | Phase 343 | Implemented / audit pending |
| PLAT-02 | Phase 343 | Implemented / audit pending |
| PLAT-03 | Phase 343 | Implemented / audit pending |
| PLAT-04 | Phase 343 | Implemented / audit pending |
| PLAT-05 | Phase 344 | Implemented / audit pending |
| PLAT-06 | Phase 344 | Implemented / audit pending |
| PLAT-07 | Phase 344 | Implemented / audit pending |
| PLAT-08 | Phase 344 | Implemented / audit pending |
| PLAT-09 | Phase 345 | Implemented / audit pending |
| PLAT-10 | Phase 345 | Implemented / audit pending |
| PLAT-11 | Phase 345 | Implemented / audit pending |
| PLAT-12 | Phase 346 | Implemented / audit pending |
| PLAT-13 | Phase 346 | Implemented / audit pending |
| PLAT-14 | Phase 346 | Implemented / audit pending |
| PLAT-15 | Phase 346 | Implemented / audit pending |
| STRAT-01 | Phase 347 | Implemented / audit pending |
| STRAT-02 | Phase 347 | Implemented / audit pending |
| STRAT-03 | Phase 347 | Implemented / audit pending |
| STRAT-04 | Phase 347 | Implemented / audit pending |
| STRAT-05 | Phase 348 | Implemented / audit pending |
| STRAT-06 | Phase 348 | Implemented / audit pending |
| STRAT-07 | Phase 348 | Implemented / audit pending |
| STRAT-08 | Phase 348 | Implemented / audit pending |
| STRAT-09 | Phase 349 | Implemented / audit pending |
| STRAT-10 | Phase 349 | Implemented / audit pending |
| STRAT-11 | Phase 349 | Implemented / audit pending |
| STRAT-12 | Phase 350 | Implemented / audit pending |
| STRAT-13 | Phase 350 | Implemented / audit pending |
| STRAT-14 | Phase 350 | Implemented / audit pending |
| STRAT-15 | Phase 350 | Implemented / audit pending |
| SPEC-01 | Phase 351 | Implemented / audit pending |
| SPEC-02 | Phase 351 | Implemented / audit pending |
| SPEC-03 | Phase 351 | Implemented / audit pending |
| SPEC-04 | Phase 351 | Implemented / audit pending |
| SPEC-05 | Phase 351 | Implemented / audit pending |
| SPEC-06 | Phase 352 | Implemented / audit pending |
| SPEC-07 | Phase 352 | Implemented / audit pending |
| SPEC-08 | Phase 352 | Implemented / audit pending |
| SPEC-09 | Phase 352 | Implemented / audit pending |
| SPEC-10 | Phase 353 | Implemented / audit pending |
| SPEC-11 | Phase 353 | Implemented / audit pending |
| SPEC-12 | Phase 353 | Implemented / audit pending |
| SPEC-13 | Phase 353 | Implemented / audit pending |
| SPEC-14 | Phase 354 | Implemented / audit pending |
| SPEC-15 | Phase 354 | Implemented / audit pending |
| SPEC-16 | Phase 354 | Implemented / audit pending |
| SPEC-17 | Phase 354 | Implemented / audit pending |
| SPEC-18 | Phase 355 | Implemented / audit pending |
| SPEC-19 | Phase 355 | Implemented / audit pending |
| SPEC-20 | Phase 355 | Implemented / audit pending |
| SPEC-21 | Phase 355 | Implemented / audit pending |
| SPEC-22 | Phase 355 | Implemented / audit pending |
| SPEC-23 | Phase 356 | Implemented / audit pending |
| SPEC-24 | Phase 356 | Implemented / audit pending |
| SPEC-25 | Phase 356 | Implemented / audit pending |
| SPEC-26 | Phase 356 | Implemented / audit pending |
| SPEC-27 | Phase 357 | Implemented / audit pending |
| SPEC-28 | Phase 357 | Implemented / audit pending |
| SPEC-29 | Phase 357 | Implemented / audit pending |
| SPEC-30 | Phase 357 | Implemented / audit pending |
| SPEC-31 | Phase 358 | Complete |
| SPEC-32 | Phase 358 | Complete |
| SPEC-33 | Phase 358 | Complete |
| SPEC-34 | Phase 358 | Complete |
| REM-01 | Phase 359 | Complete |
| REM-02 | Phase 359 | Complete |
| REM-03 | Phase 359 | Complete |
| REM-04 | Phase 360 | Complete |
| REM-05 | Phase 360 | Complete |
| REM-06 | Phase 361 | Complete |
| REM-07 | Phase 361 | Complete |
| REM-08 | Phase 361 | Complete |
| REM-09 | Phase 362 | Complete |
| REM-10 | Phase 362 | Complete |
| REM-11 | Phase 363 | Complete |
| REM-12 | Phase 363 | Complete |
| REM-13 | Phase 363 | Complete |
| ALIGN-01 | Phase 364 | Complete |
| ALIGN-02 | Phase 364 | Complete |
| ALIGN-03 | Phase 364 | Complete |
| ALIGN-04 | Phase 365 | Complete |
| ALIGN-05 | Phase 365 | Complete |
| ALIGN-06 | Phase 365 | Complete |
| ALIGN-07 | Phase 366 | Complete |
| ALIGN-08 | Phase 366 | Complete |
| ALIGN-09 | Phase 366 | Complete |
| ALIGN-10 | Phase 367 | Complete |
| FINAL-01 | Phase 368 | Complete |
| FINAL-02 | Phase 368 | Complete |
| FINAL-03 | Phase 368 | Complete |
| FINAL-04 | Phase 369 | Complete |
| FINAL-05 | Phase 369 | Complete |
| FINAL-06 | Phase 370 | Complete |
| FINAL-07 | Phase 370 | Complete |
| FINAL-08 | Phase 371 | Complete |
| FINAL-09 | Phase 371 | Complete |
| FINAL-10 | Phase 372 | Complete |
| FINAL-11 | Phase 372 | Complete |

**Coverage:**
- Universal security kernel requirements (v3.0-v3.14): 197 total, 197 mapped, 0 unmapped

## Out of Scope (v3.x)

| Feature | Reason |
|---------|--------|
| WebSocket as a primary kernel transport | WebSocket is used where required by upstream protocols (AG-UI in STRAT-10) but is not a general kernel transport surface |
| gRPC as a primary kernel transport | gRPC is used where required by upstream frameworks (Tonic in PLAT-11) but is not a general kernel transport surface |
| Agent-framework maintained plugins | Examples only; ARC is transport-layer agnostic by design |
| Mobile SDK | Web-first, CLI-first; mobile later |
| GUI admin dashboard | CLI and HTTP admin endpoints sufficient for operators |
| MERCURY domain depth | Finance-specific constructs (FIX, FpML, regulatory formats) are product-layer work, not protocol-layer |
| ARC-Wall expansion | ARC-Wall remains schema-level until the protocol substrate is production-ready |
| Ruby/PHP/Elixir substrates | Cover dominant languages first (Python, TypeScript, Go, Rust, JVM, .NET); niche languages follow demand |
| Multi-tenant SaaS UI | Focus is kernel, SDK, and middleware; hosted management console is a product-layer concern |
| Cross-kernel federation for HTTP substrates | Federation exists for protocol adapters; HTTP substrate federation follows after single-kernel adoption |

---
*Requirements defined: 2026-03-27*
*Last updated: 2026-04-14 after phase 393 ledger reconciliation updates*

## Historical Milestone Requirement Snapshots

### v2.7 Portable Trust, Certification, and Federation Maturity

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` frames portable trust,
passport portability, and cross-org trust exchange as prerequisites for the
later underwriting and market layers.
**Current boundary references:** `docs/IDENTITY_FEDERATION_GUIDE.md`,
`docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`, and `spec/PROTOCOL.md`
describe the conservative trust boundaries that `v2.7` had to preserve.

- [x] **TRUST-01**: Enterprise identity provenance is represented explicitly in
  portable credentials and federation flows without silently widening local
  authority.
- [x] **TRUST-02**: Agent Passport lifecycle state, revocation, supersession,
  and retrieval semantics are first-class for operators and relying parties.
- [x] **TRUST-03**: Certification publication and resolution work across
  operator discovery surfaces with truthful provenance, revocation, and
  supersession semantics.
- [x] **TRUST-04**: Cross-org reputation and imported trust signals remain
  evidence-backed, attenuated, and policy-visible rather than being treated as
  native local truth.
- [x] **TRUST-05**: Portable-trust distribution and federation flows remain
  conservative, documented, and regression-covered.

### v2.8 Risk, Attestation, and Launch Closure

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` ties receipts,
behavioral evidence, runtime assurance, and proof closure to the longer-term
underwriting and liability-market thesis.
**Current boundary references:** `docs/release/RELEASE_CANDIDATE.md`,
`spec/PROTOCOL.md`, and `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
describe the shipped risk export, attestation, and launch-quality proof
surfaces.

- [x] **RISK-01**: ARC exposes a signed insurer-facing behavioral feed built
  from truthful receipt, governed-action, reputation, and settlement evidence.
- [x] **RISK-02**: Runtime attestation evidence binds to issuance, approval,
  and economic ceilings through explicit runtime-assurance tiers.
- [x] **RISK-03**: Formal/spec/runtime drift is reduced to an explicitly
  accepted executable evidence boundary before launch claims are made.
- [x] **RISK-04**: ARC ships a concrete GA decision package with qualification,
  release-audit, and partner-proof artifacts.
- [x] **RISK-05**: Launch posture remains explicit about the remaining external
  dependency on hosted workflow observation before public release.

### v2.9 Economic Evidence and Authorization Context Interop

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` calls out the two-source
cost model, OAuth-family authorization details, transaction tokens, and the
need for standardized cost semantics before runtime underwriting can be
credible.
**Current boundary references:** `docs/TOOL_PRICING_GUIDE.md` says quoted price
is not the enforcement boundary, `crates/arc-kernel/src/payment.rs` already
separates pre-execution authorization from post-execution finalization, and
`docs/A2A_ADAPTER_GUIDE.md` shows ARC already interoperates with external auth
stacks but does not yet project governed economic context into those systems.

- [x] **EEI-01**: ARC defines a generic quote, cap, and post-execution cost
  evidence contract for non-payment-rail tools so truthful economics are not
  limited to x402 or ACP/shared-payment-token bridges.
- [x] **EEI-02**: ARC supports pluggable metered-cost evidence adapters that
  reconcile post-execution cost truth without mutating canonical execution
  receipts.
- [x] **EEI-03**: Governed intents, approvals, and receipts can map to
  authorization-details or equivalent transaction-context structures that
  external IAM and authorization systems can understand.
- [x] **EEI-04**: Delegated call-chain context is captured in approval and
  receipt surfaces without silently widening trust, identity, or billing
  authority.
- [x] **EEI-05**: Operator tooling, documentation, and qualification artifacts
  make ARC's economic evidence and authorization context legible to finance,
  IAM, and partner reviewers.

## Current And Planned Milestone Requirements

### v2.65 MERCURY Portfolio Revenue Boundary Qualification, Commercial Handoff, and Channel Boundary

**Research basis:** `docs/mercury/PROGRAM_FAMILY.md`,
`docs/mercury/PROGRAM_FAMILY_DECISION_RECORD.md`,
`docs/mercury/GO_TO_MARKET.md`, `docs/mercury/README.md`, and
`.planning/v2.64-MILESTONE-AUDIT.md` together define the next honest step:
prove one bounded Mercury portfolio-revenue-boundary lane over the existing
program-family package rather than widening into generic revenue operations
systems, forecasting stacks, billing platforms, channel programs, or ARC
commercial surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`,
`docs/mercury/PORTFOLIO_REVENUE_BOUNDARY.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.64`
proves one bounded program-family lane. Phases `269` through `272` must stay
Mercury-specific and must not introduce generic revenue operations systems,
forecasting stacks, billing platforms, channel programs, merged shells, ARC
commercial control surfaces, or renewed product logic inside ARC control-
plane, kernel, receipt-store, or generic CLI surfaces.

- [x] **MRB-01**: Mercury freezes one bounded portfolio-revenue-boundary and
  commercial-handoff motion over its existing dedicated app surface without
  reopening ARC generic boundary work.
- [x] **MRB-02**: Mercury defines one bounded portfolio-revenue-boundary
  package and commercial-review contract rooted in the existing program-
  family, third-program, second-portfolio-program, portfolio-program,
  second-account-expansion, renewal-qualification, delivery-continuity,
  selective-account-activation, broader-distribution, reference-
  distribution, controlled-adoption, release-readiness, trust-network,
  assurance, proof, and inquiry artifacts.
- [x] **MRB-03**: Mercury publishes one commercial approval, channel-boundary
  rule set, and handoff model that stays product-owned.
- [x] **MRB-04**: Mercury validates one portfolio-revenue-boundary package end
  to end without implying generic revenue operations systems, forecasting
  stacks, billing platforms, channel programs, merged shells, or ARC
  commercial control surfaces.
- [x] **MRB-05**: The milestone ends with one explicit proceed or defer
  decision for bounded portfolio-revenue-boundary expansion.

### v2.64 MERCURY Program Family Qualification, Shared Review Package, and Portfolio Claim Discipline

**Research basis:** `docs/mercury/THIRD_PROGRAM.md`,
`docs/mercury/THIRD_PROGRAM_DECISION_RECORD.md`,
`docs/mercury/GO_TO_MARKET.md`, `docs/mercury/README.md`, and
`.planning/v2.63-MILESTONE-AUDIT.md` together define the next honest step:
prove one bounded Mercury program-family lane over the existing third-program
package rather than widening into generic portfolio-management tooling,
revenue operations systems, forecasting stacks, billing platforms, channel
programs, or ARC commercial surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`, `docs/mercury/PROGRAM_FAMILY.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.63`
proves one bounded third-program lane. Phases `265` through `268` must stay
Mercury-specific and must not introduce generic portfolio-management tooling,
revenue operations systems, forecasting stacks, billing platforms, channel
programs, merged shells, ARC commercial control surfaces, or renewed product
logic inside ARC control-plane, kernel, receipt-store, or generic CLI
surfaces.

- [x] **MPF-01**: Mercury freezes one bounded program-family and shared-review
  motion over its existing dedicated app surface without reopening ARC generic
  boundary work.
- [x] **MPF-02**: Mercury defines one bounded program-family package and
  shared-review contract rooted in the existing third-program, second-
  portfolio-program, portfolio-program, second-account-expansion, renewal-
  qualification, delivery-continuity, selective-account-activation,
  broader-distribution, reference-distribution, controlled-adoption,
  release-readiness, trust-network, assurance, proof, and inquiry artifacts.
- [x] **MPF-03**: Mercury publishes one family approval, portfolio-claim
  discipline, and handoff model that stays product-owned.
- [x] **MPF-04**: Mercury validates one program-family package end to end
  without implying generic portfolio-management tooling, revenue operations
  systems, forecasting stacks, billing platforms, channel programs, merged
  shells, or ARC commercial control surfaces.
- [x] **MPF-05**: The milestone ends with one explicit proceed or defer
  decision for bounded program-family expansion.

### v2.63 MERCURY Third Program Qualification, Reuse Repeatability, and Multi-Program Boundary

**Research basis:** `docs/mercury/SECOND_PORTFOLIO_PROGRAM.md`,
`docs/mercury/SECOND_PORTFOLIO_PROGRAM_DECISION_RECORD.md`,
`docs/mercury/GO_TO_MARKET.md`, `docs/mercury/README.md`, and
`.planning/v2.62-MILESTONE-AUDIT.md` together define the next honest step by
deferred-scope inference: prove one additional explicitly named third-program
lane over the existing second-portfolio-program package rather than widening
into generic portfolio-management tooling, revenue operations systems,
forecasting stacks, billing platforms, channel programs, or ARC commercial
surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`, `docs/mercury/SECOND_PORTFOLIO_PROGRAM.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.62`
proves one bounded second-portfolio-program lane. Phases `261` through `264`
must stay Mercury-specific and must not introduce generic portfolio-
management tooling, account-management platforms, customer-success
workflows, revenue operations systems, forecasting stacks, billing
platforms, channel programs, merged shells, or renewed product logic inside
ARC control-plane, kernel, receipt-store, or generic CLI surfaces.

- [x] **MTP-01**: Mercury freezes one bounded third-program and repeated
  portfolio-reuse motion over its existing dedicated app surface without
  reopening ARC generic boundary work.
- [x] **MTP-02**: Mercury defines one bounded third-program package and
  repeated portfolio-reuse contract rooted in the existing second-portfolio-
  program, portfolio-program, second-account-expansion, renewal-
  qualification, delivery-continuity, selective-account-activation,
  broader-distribution, reference-distribution, controlled-adoption,
  release-readiness, trust-network, assurance, proof, and inquiry artifacts.
- [x] **MTP-03**: Mercury publishes one approval-refresh, multi-program
  guardrail, and third-program handoff model that stays product-owned.
- [x] **MTP-04**: Mercury validates one third-program package end to end
  without implying generic portfolio-management tooling, revenue operations
  systems, forecasting stacks, billing platforms, channel programs, merged
  shells, or ARC commercial control surfaces.
- [x] **MTP-05**: The milestone ends with one explicit proceed or defer
  decision for bounded third-program expansion.

### v2.62 MERCURY Second Portfolio Program Qualification, Reuse Discipline, and Revenue Boundary

**Research basis:** `docs/mercury/PORTFOLIO_PROGRAM.md`,
`docs/mercury/PORTFOLIO_PROGRAM_DECISION_RECORD.md`,
`docs/mercury/GO_TO_MARKET.md`, `docs/mercury/README.md`, and
`.planning/v2.61-MILESTONE-AUDIT.md` together define the next honest step:
prove one bounded Mercury second-portfolio-program lane over the existing
portfolio-program package rather than widening into generic portfolio-
management tooling, revenue operations systems, forecasting stacks, billing
platforms, channel programs, or ARC commercial surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`, `docs/mercury/PORTFOLIO_PROGRAM.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.61`
proves one bounded portfolio-program lane. Phases `257` through `260` must
stay Mercury-specific and must not introduce generic portfolio-management
tooling, account-management platforms, revenue operations systems,
forecasting stacks, billing platforms, channel programs, merged shells, ARC
commercial control surfaces, or renewed product logic inside ARC control-
plane, kernel, receipt-store, or generic CLI surfaces.

- [x] **MSP-01**: Mercury freezes one bounded second-portfolio-program and
  portfolio-reuse motion over its existing dedicated app surface without
  reopening ARC generic boundary work.
- [x] **MSP-02**: Mercury defines one bounded second-portfolio-program
  package and portfolio-reuse contract rooted in the existing portfolio-
  program, second-account-expansion, renewal-qualification, delivery-
  continuity, selective-account-activation, broader-distribution, reference-
  distribution, controlled-adoption, release-readiness, trust-network,
  assurance, proof, and inquiry artifacts.
- [x] **MSP-03**: Mercury publishes one portfolio-reuse approval, revenue-
  boundary guardrail, and second-program handoff model that stays
  product-owned.
- [x] **MSP-04**: Mercury validates one second-portfolio-program package end
  to end without implying generic portfolio-management tooling, revenue
  operations systems, forecasting stacks, billing platforms, channel
  programs, merged shells, or ARC commercial control surfaces.
- [x] **MSP-05**: The milestone ends with one explicit proceed or defer
  decision for bounded second-portfolio-program expansion.

### v2.61 MERCURY Portfolio Program Qualification, Multi-Account Boundary, and Revenue Operations Guardrails

**Research basis:** `docs/mercury/SECOND_ACCOUNT_EXPANSION.md`,
`docs/mercury/SECOND_ACCOUNT_EXPANSION_DECISION_RECORD.md`,
`docs/mercury/GO_TO_MARKET.md`, `docs/mercury/README.md`, and
`.planning/v2.60-MILESTONE-AUDIT.md` together define the next honest step:
prove one bounded Mercury portfolio-program lane over the existing
second-account-expansion package rather than widening into generic customer-
success tooling, account-management platforms, revenue operations systems,
channel marketplaces, or ARC commercial surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`,
`docs/mercury/SECOND_ACCOUNT_EXPANSION.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.60`
proves one bounded second-account-expansion lane. Phases `253` through `256`
must stay Mercury-specific and must not introduce generic customer-success
tooling, account-management platforms beyond one explicitly bounded
multi-account program, revenue operations systems, channel marketplaces,
merged shells, ARC commercial control surfaces, or renewed product logic
inside ARC control-plane, kernel, receipt-store, or generic CLI surfaces.

- [x] **MPP-01**: Mercury freezes one bounded portfolio-program and program-
  review motion over its existing dedicated app surface without reopening ARC
  generic boundary work.
- [x] **MPP-02**: Mercury defines one bounded portfolio-program package and
  program-review contract rooted in the existing second-account-expansion,
  renewal-qualification, delivery-continuity, selective-account-activation,
  broader-distribution, reference-distribution, controlled-adoption,
  release-readiness, trust-network, assurance, proof, and inquiry artifacts.
- [x] **MPP-03**: Mercury publishes one portfolio approval, revenue
  operations guardrail, and program handoff model that stays product-owned.
- [x] **MPP-04**: Mercury validates one portfolio-program package end to end
  without implying generic customer-success tooling, account-management
  platforms, revenue operations systems, channel marketplaces, merged
  shells, or ARC commercial control surfaces.
- [x] **MPP-05**: The milestone ends with one explicit proceed or defer
  decision for bounded portfolio-program expansion.

### v2.60 MERCURY Second-Account Expansion Qualification, Portfolio Boundary, and Reuse Governance

**Research basis:** `docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/RENEWAL_QUALIFICATION_DECISION_RECORD.md`,
`docs/mercury/RENEWAL_QUALIFICATION_VALIDATION_PACKAGE.md`,
`docs/mercury/README.md`, and `.planning/v2.59-MILESTONE-AUDIT.md` together
define the next honest step: prove one bounded Mercury second-account
expansion lane over the existing renewal-qualification package rather than
widening into generic customer-success tooling, account-management platforms,
multi-account renewal programs, channel marketplaces, or ARC commercial
surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`,
`docs/mercury/RENEWAL_QUALIFICATION.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.59`
proves one bounded renewal-qualification lane. Phases `249` through `252`
must stay Mercury-specific and must not introduce generic customer-success
tooling, account-management platforms, multi-account renewal programs beyond
one explicitly bounded second-account motion, channel marketplaces, merged
shells, ARC commercial control surfaces, or renewed product logic inside ARC
control-plane, kernel, receipt-store, or generic CLI surfaces.

- [x] **MEX-01**: Mercury freezes one bounded second-account expansion and
  portfolio-review motion over its existing dedicated app surface without
  reopening ARC generic boundary work.
- [x] **MEX-02**: Mercury defines one bounded expansion-readiness package and
  portfolio-review contract rooted in the existing renewal-qualification,
  delivery-continuity, selective-account-activation, broader-distribution,
  reference-distribution, controlled-adoption, release-readiness,
  trust-network, assurance, proof, and inquiry artifacts.
- [x] **MEX-03**: Mercury publishes one expansion approval, reuse-governance,
  and second-account handoff model that stays product-owned.
- [x] **MEX-04**: Mercury validates one second-account expansion package end
  to end without implying generic customer-success tooling, account-
  management platforms, multi-account renewal programs, channel marketplaces,
  merged shells, or ARC commercial control surfaces.
- [x] **MEX-05**: The milestone ends with one explicit proceed or defer
  decision for bounded second-account expansion.

### v2.59 MERCURY Renewal Qualification, Outcome Review, and Expansion Boundary

**Research basis:** `docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/DELIVERY_CONTINUITY_DECISION_RECORD.md`,
`docs/mercury/DELIVERY_CONTINUITY_VALIDATION_PACKAGE.md`,
`docs/mercury/README.md`, and `.planning/v2.58-MILESTONE-AUDIT.md` together
define the next honest step: prove one bounded Mercury renewal lane over the
existing delivery-continuity package rather than widening into generic
customer-success tooling, CRM workflows, account-management platforms, channel
marketplaces, or ARC commercial surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`,
`docs/mercury/DELIVERY_CONTINUITY.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.58`
proves one bounded delivery-continuity lane. Phases `245` through `248` must
stay Mercury-specific and must not introduce generic customer-success tooling,
CRM workflows, account-management platforms, channel marketplaces, merged
shells, ARC commercial control surfaces, or renewed product logic inside ARC
control-plane, kernel, receipt-store, or generic CLI surfaces.

- [x] **MRN-01**: Mercury freezes one bounded renewal qualification and
  outcome-review motion over its existing dedicated app surface without
  reopening ARC generic boundary work.
- [x] **MRN-02**: Mercury defines one bounded renewal package and outcome-
  review contract rooted in the existing delivery-continuity, selective-
  account-activation, broader-distribution, reference-distribution,
  controlled-adoption, release-readiness, trust-network, assurance, proof,
  and inquiry artifacts.
- [x] **MRN-03**: Mercury publishes one renewal-approval, reference-reuse
  discipline, and expansion-boundary handoff model that stays product-owned.
- [x] **MRN-04**: Mercury validates one renewal package end to end without
  implying generic customer-success tooling, CRM workflows, account-management
  platforms, channel marketplaces, merged shells, or ARC commercial control
  surfaces.
- [x] **MRN-05**: The milestone ends with one explicit renew or defer
  decision for bounded Mercury renewal.

### v2.58 MERCURY Controlled Delivery Continuity, Outcome Evidence, and Renewal Gate

**Research basis:** `docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_DECISION_RECORD.md`,
`docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_VALIDATION_PACKAGE.md`,
`docs/mercury/README.md`, and `.planning/v2.57-MILESTONE-AUDIT.md` together
define the next honest step: prove one bounded Mercury controlled-delivery
continuity lane over the existing selective-account-activation package rather
than widening into generic onboarding tooling, CRM workflows, support desks,
channel marketplaces, or ARC commercial surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`,
`docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.57`
proves one bounded selective-account-activation lane. Phases `241` through
`244` must stay Mercury-specific and must not introduce generic onboarding
tooling, CRM workflows, support desks, channel marketplaces, merged shells,
ARC commercial control surfaces, or renewed product logic inside ARC control-
plane, kernel, receipt-store, or generic CLI surfaces.

- [x] **MDC-01**: Mercury freezes one bounded controlled-delivery continuity
  and renewal-gate motion over its existing dedicated app surface without
  reopening ARC generic boundary work.
- [x] **MDC-02**: Mercury defines one bounded delivery-continuity package and
  outcome-evidence contract rooted in the existing selective-account-
  activation, broader-distribution, reference-distribution, controlled-
  adoption, release-readiness, trust-network, assurance, proof, and inquiry
  artifacts.
- [x] **MDC-03**: Mercury publishes one renewal-gate, delivery-escalation,
  and customer-evidence handoff model that stays product-owned.
- [x] **MDC-04**: Mercury validates one controlled-delivery continuity package
  end to end without implying generic onboarding tooling, CRM workflows,
  support desks, channel marketplaces, merged shells, or ARC commercial
  control surfaces.
- [x] **MDC-05**: The milestone ends with one explicit proceed or defer
  renewal decision for controlled-delivery continuity.

### v2.57 MERCURY Selective Account Activation, Controlled Delivery, and Claim Containment

**Research basis:** `docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/BROADER_DISTRIBUTION_DECISION_RECORD.md`,
`docs/mercury/BROADER_DISTRIBUTION_VALIDATION_PACKAGE.md`,
`docs/mercury/README.md`, and `.planning/v2.56-MILESTONE-AUDIT.md` together
define the next honest step: qualify one bounded Mercury selective-account
activation lane over the existing broader-distribution package rather than
widening into generic onboarding tooling, CRM workflows, channel
marketplaces, or ARC commercial surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`,
`docs/mercury/BROADER_DISTRIBUTION.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.56`
proves one bounded broader-distribution lane. Phases `237` through `240`
must stay Mercury-specific and must not introduce generic onboarding tooling,
CRM workflows, channel marketplaces, merged shells, ARC commercial control
surfaces, or renewed product logic inside ARC control-plane, kernel,
receipt-store, or generic CLI surfaces.

- [x] **MSA-01**: Mercury freezes one bounded selective-account activation
  and controlled-delivery motion over its existing dedicated app surface
  without reopening ARC generic boundary work.
- [x] **MSA-02**: Mercury defines one bounded activation package and
  controlled-delivery contract rooted in the existing broader-distribution,
  reference-distribution, controlled-adoption, release-readiness,
  trust-network, assurance, proof, and inquiry artifacts.
- [x] **MSA-03**: Mercury publishes one claim-containment, activation-
  approval-refresh, and customer-handoff model that stays product-owned.
- [x] **MSA-04**: Mercury validates one selective-account activation package
  end to end without implying generic onboarding tooling, CRM workflows,
  channel marketplaces, merged shells, or ARC commercial control surfaces.
- [x] **MSA-05**: The milestone ends with one explicit proceed or defer
  decision for selective-account activation.

### v2.56 MERCURY Broader Distribution Readiness, Selective Account Qualification, and Claim Governance

**Research basis:** `docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/REFERENCE_DISTRIBUTION_DECISION_RECORD.md`,
`docs/mercury/REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE.md`,
`docs/mercury/README.md`, and `.planning/v2.55-MILESTONE-AUDIT.md` together
define the next honest step: qualify one bounded Mercury broader-distribution
readiness lane over the existing reference-distribution package rather than
widening into generic sales tooling, CRM workflows, or ARC commercial
surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`,
`docs/mercury/REFERENCE_DISTRIBUTION.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.55`
proves one bounded reference-distribution lane. Phases `233` through `236`
must stay Mercury-specific and must not introduce generic sales tooling, CRM
workflows, merged shells, ARC commercial control surfaces, or renewed product
logic inside ARC control-plane, kernel, receipt-store, or generic CLI
surfaces.

- [x] **MBD-01**: Mercury freezes one bounded broader-distribution and
  selective account-qualification motion over its existing dedicated app
  surface without reopening ARC generic boundary work.
- [x] **MBD-02**: Mercury defines one bounded qualification package and
  governed-distribution contract rooted in the existing reference-
  distribution, controlled-adoption, release-readiness, trust-network,
  assurance, proof, and inquiry artifacts.
- [x] **MBD-03**: Mercury publishes one claim-governance, selective account-
  approval, and distribution-handoff model that stays product-owned.
- [x] **MBD-04**: Mercury validates one broader-distribution package end to
  end without implying generic sales tooling, CRM workflows, merged shells,
  or ARC commercial control surfaces.
- [x] **MBD-05**: The milestone ends with one explicit proceed or defer
  decision for broader Mercury distribution.

### v2.55 MERCURY Reference Distribution, Landed-Account Expansion, and Claim Discipline

**Research basis:** `docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/CONTROLLED_ADOPTION_DECISION_RECORD.md`,
`docs/mercury/CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md`,
`docs/mercury/README.md`, and `.planning/v2.54-MILESTONE-AUDIT.md` together
define the next honest step: qualify one bounded Mercury reference-
distribution and landed-account expansion lane over the existing
controlled-adoption package rather than widening into generic sales tooling
or ARC commercial surfaces.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`, `docs/mercury/CONTROLLED_ADOPTION.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.54`
proves one bounded controlled-adoption lane. Phases `229` through `232` must
stay Mercury-specific and must not introduce generic sales tooling, merged
shells, ARC commercial control surfaces, or renewed product logic inside ARC
control-plane, kernel, receipt-store, or generic CLI surfaces.

- [x] **MRE-01**: Mercury freezes one bounded reference-distribution and
  landed-account expansion motion over its existing dedicated app surface
  without reopening ARC generic boundary work.
- [x] **MRE-02**: Mercury defines one bounded reference package and expansion-
  evidence contract rooted in the existing controlled-adoption, release-
  readiness, trust-network, assurance, proof, and inquiry artifacts.
- [x] **MRE-03**: Mercury publishes one claim-discipline, buyer-reference
  approval, and sales-handoff model that stays product-owned.
- [x] **MRE-04**: Mercury validates one reference-backed expansion package end
  to end without implying generic sales tooling, merged shells, or ARC
  commercial control surfaces.
- [x] **MRE-05**: The milestone ends with one explicit proceed or defer
  decision for broader landed-account distribution.

### v2.54 MERCURY Controlled Adoption, Renewal Evidence, and Reference Readiness

**Research basis:** `docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/RELEASE_READINESS_DECISION_RECORD.md`,
`docs/mercury/RELEASE_READINESS_VALIDATION_PACKAGE.md`,
`docs/mercury/README.md`, and `.planning/v2.53-MILESTONE-AUDIT.md` together
define the next honest step: qualify one bounded post-launch Mercury adoption
lane for renewal and reference evidence on top of the existing release-
readiness package.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`,
`docs/mercury/RELEASE_READINESS.md`,
`docs/mercury/GO_TO_MARKET.md`, and `spec/PROTOCOL.md` define the Mercury app
surface and the generic ARC substrate it must continue to consume without
polluting.
**Execution dependency note:** This milestone starts only after `v2.53`
launches one bounded Mercury release-readiness lane. Phases `225` through
`228` must stay Mercury-specific and must not reintroduce Mercury product
logic into ARC control-plane, kernel, receipt-store, or generic CLI surfaces.

- [x] **MCA-01**: Mercury freezes one controlled-adoption cohort and post-
  launch scope over its existing dedicated app surface without reopening ARC
  generic boundary work.
- [x] **MCA-02**: Mercury defines one bounded adoption-evidence and renewal
  package contract rooted in the existing release-readiness, trust-network,
  assurance, proof, and inquiry artifacts.
- [x] **MCA-03**: Mercury publishes one customer-success, reference-readiness,
  and support-escalation model that stays product-owned.
- [x] **MCA-04**: Mercury validates one controlled-adoption package end to end
  without implying broader delivery surfaces, a merged shell, or generic ARC
  release tooling.
- [x] **MCA-05**: The milestone ends with one explicit scale or defer decision
  for broader Mercury rollout.

### v2.53 MERCURY Release Readiness, Partner Delivery, and Controlled Adoption

**Research basis:** `docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/PILOT_RUNBOOK.md`,
`docs/mercury/ASSURANCE_SUITE_VALIDATION_PACKAGE.md`,
`docs/mercury/TRUST_NETWORK_DECISION_RECORD.md`, and
`.planning/v2.52-MILESTONE-AUDIT.md` together define the next honest step:
Mercury-specific release packaging over the already-corrected ARC substrate.
**Current boundary references:** `crates/arc-mercury/src/main.rs`,
`crates/arc-mercury/src/commands.rs`,
`docs/mercury/README.md`,
`docs/mercury/GO_TO_MARKET.md`, and
`spec/PROTOCOL.md` define the Mercury app surface and the generic ARC
substrate it must consume without polluting.
**Execution dependency note:** This milestone starts only after `v2.52`
restores ARC purity. Phases `221` through `224` must stay Mercury-specific and
must not reintroduce Mercury product logic into ARC control-plane, kernel,
receipt-store, or generic CLI surfaces.

- [x] **MRR-01**: Mercury freezes one release-readiness scope and audience set
  over its existing dedicated app surface without reopening ARC generic
  boundary work.
- [x] **MRR-02**: Mercury defines one bounded reviewer and partner delivery
  package contract rooted in existing proof, inquiry, assurance, and trust-
  network artifacts.
- [x] **MRR-03**: Mercury publishes one operator-facing release, escalation,
  and support-handoff model that stays product-owned.
- [x] **MRR-04**: Mercury validates one release-readiness package end to end
  without implying a new product line, merged shell, or generic ARC console.
- [x] **MRR-05**: The milestone ends with one explicit launch or hold decision
  for Mercury itself.

### v2.52 MERCURY Extensions ARC Purity Restoration, Boundary Cleanup, and Qualification

**Research basis:** the user correction that ARC must stay pure and not
specific to Mercury, plus the repo state in
`crates/arc-control-plane/src/product_surface.rs`,
`crates/arc-kernel/src/receipt_query.rs`,
`crates/arc-cli/src/main.rs`,
`crates/arc-cli/src/trust_control.rs`, and
`crates/arc-store-sqlite/src/receipt_store.rs` after `v2.51` showed ARC-side
product coupling that had to be removed rather than hardened further.
**Current boundary references:** `crates/arc-control-plane/src/lib.rs`,
`crates/arc-kernel/src/receipt_query.rs`,
`crates/arc-cli/src/main.rs`,
`crates/arc-cli/src/trust_control.rs`,
`crates/arc-store-sqlite/src/receipt_store.rs`, and
`crates/arc-store-sqlite/Cargo.toml` now define the corrected ARC boundary.
**Execution dependency note:** This milestone superseded the stale
ARC-side `product-surface` direction before any further Mercury milestone was
allowed to proceed.

- [x] **MAP-01**: ARC does not expose Mercury- or ARC-Wall-specific
  `product-surface` entrypoints in generic control-plane or CLI crates.
- [x] **MAP-02**: ARC's generic receipt query and trust-control surfaces do
  not name Mercury-only filters.
- [x] **MAP-03**: ARC's generic SQLite receipt store does not depend on
  `arc-mercury-core` or maintain a Mercury-only receipt index.
- [x] **MAP-04**: A repo-wide audit of generic ARC crates returns no Mercury or
  ARC-Wall references outside dedicated app crates.
- [x] **MAP-05**: The milestone ends with low-memory validation evidence and
  one explicit decision to keep Mercury release work on Mercury's own app
  surface.

### v2.51 MERCURY Extensions Shared Service Boundaries, Cross-Product Governance, and Platform Hardening

**Research basis:** `docs/mercury/epics/MASTER_PROJECT.md`,
`docs/mercury/epics/PHASE_4_5_TICKETS.md`,
`docs/mercury/IMPLEMENTATION_ROADMAP.md`,
`docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/TECHNICAL_ARCHITECTURE.md`, and
`docs/arc-wall/README.md` define the post-ARC-Wall `E-026` hardening ladder
as the next bounded step after the first companion-product lane is validated.
**Current boundary references:** `.planning/v2.50-MILESTONE-AUDIT.md`,
`docs/mercury/ARC_WALL_BRIEF.md`,
`docs/arc-wall/README.md`,
`crates/arc-mercury/src/main.rs`,
`crates/arc-wall/src/main.rs`, and
`spec/PROTOCOL.md` define the current ARC substrate plus separate MERCURY and
ARC-Wall app boundaries that the hardening work must preserve rather than
collapse.
**Execution dependency note:** This milestone starts only after `v2.50`
validates one ARC-Wall lane. Phases `213` through `216` must freeze shared
service boundaries and cross-product governance across the validated MERCURY
and ARC-Wall products on ARC, and avoid widening into new buyer motions, new
connector families, or collapsing the products into one surface.

- [x] **MPH-01**: Shared ARC substrate seams and product-specific surfaces are
  explicit across MERCURY and ARC-Wall rather than being inferred from
  implementation drift.
- [x] **MPH-02**: Cross-product governance, release, incident, and trust-
  material ownership are defined for the current MERCURY plus ARC-Wall
  product set.
- [x] **MPH-03**: Shared service reuse stays rooted in ARC's generic substrate
  and does not collapse MERCURY or ARC-Wall into a merged shell or generic
  platform console.
- [x] **MPH-04**: One bounded platform-hardening backlog is published with
  dependency order, qualification expectations, and owner hints for sustained
  multi-product support.
- [x] **MPH-05**: The milestone ends with one validated operating boundary and
  explicit next-step decision rather than implicit buyer-sprawl or product-
  merger assumptions.

### v2.50 ARC-Wall Companion Product Core, Guard Evidence, and Buyer Motion

**Research basis:** `docs/mercury/ARC_WALL_BRIEF.md`,
`docs/mercury/IMPLEMENTATION_ROADMAP.md`,
`docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/TECHNICAL_ARCHITECTURE.md`,
`docs/mercury/epics/MASTER_PROJECT.md`, and
`docs/mercury/epics/PHASE_4_5_TICKETS.md` define ARC-Wall as the next
Phase 5 program after trust-network work and frame it as a companion product
built on ARC rather than part of MERCURY's trading-workflow surface.
**Current boundary references:** `.planning/v2.49-MILESTONE-AUDIT.md`,
`docs/mercury/TRUST_NETWORK_DECISION_RECORD.md`,
`docs/mercury/ARC_WALL_BRIEF.md`,
`docs/mercury/README.md`,
`spec/PROTOCOL.md`, and
`crates/arc-mercury/src/main.rs` define the validated ARC substrate,
Mercury app boundary, and trust-network artifacts that ARC-Wall work must
reuse rather than collapse together.
**Execution dependency note:** This milestone starts only after `v2.49`
validates the first trust-network lane. Phases `209` through `212` must keep
expansion limited to one ARC-Wall buyer path, reuse the same ARC substrate
and publication truth, and avoid widening into multi-product hardening,
generic barrier-platform breadth, or folding ARC-Wall into MERCURY.

- [x] **AWALL-01**: ARC-Wall selects and freezes one information-domain
  separation buyer motion and one control-team boundary rather than opening
  several barrier or compliance programs at once.
- [x] **AWALL-02**: ARC-Wall can define one machine-readable information-
  domain evidence schema rooted in ARC receipt, checkpoint, publication, and
  verification truth without redefining ARC or MERCURY semantics.
- [x] **AWALL-03**: ARC-Wall can support one bounded control-path guard and
  evaluation surface with explicit policy reference, allow/deny evidence, and
  fail-closed control semantics.
- [x] **AWALL-04**: ARC-Wall remains a companion product on ARC rather than a
  MERCURY feature expansion, generic barrier platform, or premature
  multi-product hardening program.
- [x] **AWALL-05**: The milestone ends with one validated buyer package,
  operating model, and explicit next-step boundary rather than implicit
  platform-hardening or buyer-sprawl assumptions.

### v2.49 MERCURY Trust Network Witness, Publication, and Proof-Profile Interoperability

**Research basis:** `docs/mercury/IMPLEMENTATION_ROADMAP.md`,
`docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/PARTNERSHIP_STRATEGY.md`,
`docs/mercury/TECHNICAL_ARCHITECTURE.md`,
`docs/mercury/epics/MASTER_PROJECT.md`, and
`docs/mercury/epics/PHASE_4_5_TICKETS.md` define Trust Network as the next
Phase 5 track after one bounded embedded OEM lane is validated.
**Current boundary references:** `.planning/v2.48-MILESTONE-AUDIT.md`,
`docs/mercury/EMBEDDED_OEM_DECISION_RECORD.md`,
`docs/mercury/EMBEDDED_OEM.md`,
`docs/mercury/README.md`,
`crates/arc-mercury/src/main.rs`, and
`crates/arc-mercury/src/commands.rs` define the validated proof,
publication, reviewer, assurance, and embedded-OEM surfaces that trust-
network work must reuse rather than replace.
**Execution dependency note:** This milestone starts only after `v2.48`
validates the first embedded OEM lane. Phases `205` through `208` must keep
expansion limited to one trust-network path, reuse the same ARC/MERCURY truth
artifacts, and avoid widening into ARC-Wall, multi-network trust services, or
generic ecosystem infrastructure.

- [x] **TRUSTNET-01**: MERCURY selects and freezes one trust-network sponsor
  boundary and one sharing model for reviewers or firms rather than opening a
  generic ecosystem program all at once.
- [x] **TRUSTNET-02**: MERCURY can define one machine-readable trust-anchor,
  witness, and publication-continuity contract rooted in the existing proof,
  inquiry, and publication artifacts without redefining ARC truth.
- [x] **TRUSTNET-03**: MERCURY can align one bounded shared proof-profile
  interoperability surface for reviewer or partner distribution without
  breaking existing Mercury verifier equivalence.
- [x] **TRUSTNET-04**: Trust-network work remains limited to one shared
  publication and witness lane and does not turn MERCURY into a generic
  ecosystem service, multi-network trust broker, or ARC-Wall companion
  product.
- [x] **TRUSTNET-05**: The milestone ends with one validated rollout plan,
  operating model, and explicit next-step boundary rather than implicit
  ARC-Wall or multi-product sprawl.

### v2.48 MERCURY Embedded OEM Distribution, Partner Packaging, and Bounded SDK Surface

**Research basis:** `docs/mercury/IMPLEMENTATION_ROADMAP.md`,
`docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/PARTNERSHIP_STRATEGY.md`,
`docs/mercury/epics/MASTER_PROJECT.md`, and
`docs/mercury/epics/PHASE_4_5_TICKETS.md` define embedded OEM distribution as
the next Phase 5 track after downstream and assurance consumption paths are
validated.
**Current boundary references:** `.planning/v2.47-MILESTONE-AUDIT.md`,
`docs/mercury/ASSURANCE_SUITE_DECISION_RECORD.md`,
`docs/mercury/DOWNSTREAM_REVIEW_DECISION_RECORD.md`,
`docs/mercury/README.md`,
`crates/arc-mercury/src/main.rs`, and
`crates/arc-mercury/src/commands.rs` define the validated reviewer,
governance, downstream, and assurance surfaces that embedded OEM work must
reuse rather than replace.
**Execution dependency note:** This milestone starts only after `v2.47`
validates the first assurance-suite lane. Phases `201` through `204` must
keep expansion limited to one embedded OEM path, reuse the same ARC/MERCURY
truth artifacts, and avoid widening into multi-partner OEM breadth,
trust-network services, ARC-Wall, or a generic SDK platform.

- [x] **OEM-01**: MERCURY selects and freezes one embedded OEM distribution
  path and partner boundary for the next expansion step rather than opening
  several partner or white-label programs at once.
- [x] **OEM-02**: MERCURY can define one machine-readable embedded packaging
  profile rooted in the existing proof, inquiry, reviewer, governance, and
  assurance artifacts without redefining ARC truth.
- [x] **OEM-03**: MERCURY can generate one bounded partner-facing embedded
  distribution path with explicit packaging, disclosure, and fail-closed
  delivery semantics.
- [x] **OEM-04**: Embedded distribution remains limited to one partner
  packaging surface and does not turn MERCURY into a generic SDK, portal, or
  white-label platform.
- [x] **OEM-05**: The milestone ends with one validated embedded distribution
  lane, partner operating model, and explicit next-step boundary rather than
  implicit trust-network, ARC-Wall, or multi-partner sprawl.

### v2.47 MERCURY Assurance Suite Reviewer Packages, Investigation Packaging, and External Review Readiness

**Research basis:** `docs/mercury/IMPLEMENTATION_ROADMAP.md`,
`docs/mercury/TECHNICAL_ARCHITECTURE.md`,
`docs/mercury/INVESTOR_NARRATIVE.md`,
`docs/mercury/epics/MASTER_PROJECT.md`, and
`docs/mercury/epics/PHASE_4_5_TICKETS.md` define assurance suite as the
remaining bounded phase-4 track after governance and downstream lanes are
validated.
**Current boundary references:** `.planning/v2.46-MILESTONE-AUDIT.md`,
`docs/mercury/GOVERNANCE_WORKBENCH_DECISION_RECORD.md`,
`docs/mercury/DOWNSTREAM_REVIEW_DECISION_RECORD.md`,
`docs/mercury/README.md`,
`crates/arc-mercury/src/main.rs`, and
`crates/arc-mercury/src/commands.rs` define the validated governance,
downstream, and supervised-live surfaces that assurance-suite work must reuse
rather than replace.
**Execution dependency note:** This milestone starts only after `v2.46`
validates the first governance-workbench lane. Phases `197` through `200`
must keep expansion limited to one assurance-suite lane, reuse the same
ARC/MERCURY truth artifacts, and avoid widening into a generic review portal,
OEM packaging, trust-network work, or deep runtime coupling.

- [x] **ASR-01**: MERCURY selects and freezes one assurance-suite reviewer
  population set and package family for the next expansion step rather than
  opening several reviewer or partner programs at once.
- [x] **ASR-02**: MERCURY can define one machine-readable assurance package
  family and disclosure-profile contract for internal, auditor, and
  counterparty review rooted in the existing proof, inquiry, reviewer, and
  qualification artifacts without redefining ARC truth.
- [x] **ASR-03**: MERCURY can generate one bounded reviewer-facing assurance
  export and investigation package path with explicit disclosure, redaction,
  and verifier-equivalence semantics.
- [x] **ASR-04**: Reviewer-facing assurance flows support internal, auditor,
  and counterparty populations over the same underlying artifacts without
  turning MERCURY into a generic case-management or portal product.
- [x] **ASR-05**: The milestone ends with one validated assurance workflow,
  reviewer operating model, and explicit next-step boundary rather than
  implicit OEM, trust-network, or connector sprawl.

### v2.46 MERCURY Governance Workbench Approval, Release, and Exception Controls

**Research basis:** `docs/mercury/IMPLEMENTATION_ROADMAP.md`,
`docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/PARTNERSHIP_STRATEGY.md`,
`docs/mercury/epics/MASTER_PROJECT.md`, and
`docs/mercury/epics/PHASE_4_5_TICKETS.md` define governance workbench as one
of the bounded phase-4 tracks that can follow the first downstream consumer
lane once expansion remains narrow.
**Current boundary references:** `.planning/v2.45-MILESTONE-AUDIT.md`,
`docs/mercury/DOWNSTREAM_REVIEW_DECISION_RECORD.md`,
`docs/mercury/SUPERVISED_LIVE_DECISION_RECORD.md`,
`docs/mercury/README.md`,
`crates/arc-mercury/src/main.rs`, and
`crates/arc-mercury/src/commands.rs` define the validated downstream and
supervised-live surfaces that governance workflow support must reuse rather
than replace.
**Execution dependency note:** This milestone starts only after `v2.45`
validates the first downstream case-management review lane. Phases `193`
through `196` must keep expansion limited to one governance-workbench
workflow, reuse the same ARC/MERCURY truth artifacts, and avoid widening into
additional downstream connectors, OEM packaging, trust-network work, or deep
runtime coupling.

- [x] **GWB-01**: MERCURY selects and freezes one governance-workbench
  workflow path for the next expansion step rather than opening several
  governance or connector programs at once.
- [x] **GWB-02**: MERCURY can generate one machine-readable governance
  decision package for model, prompt, policy, parameter, and release-change
  review rooted in the existing proof and publication model without
  redefining ARC truth.
- [x] **GWB-03**: MERCURY can support one bounded release, rollback,
  approval, and exception workflow with explicit owner, state, and fail-
  closed escalation semantics.
- [x] **GWB-04**: Governance-facing reviewer packages and operational views
  support workflow owners and control teams over the same underlying
  artifacts without turning MERCURY into a generic workflow engine.
- [x] **GWB-05**: The milestone ends with one validated governance workflow,
  operating model, and explicit next-step boundary rather than implicit
  connector, OEM, or runtime-coupling sprawl.

### v2.45 MERCURY Downstream Review Distribution and Assurance Packaging

**Research basis:** `docs/mercury/IMPLEMENTATION_ROADMAP.md`,
`docs/mercury/GO_TO_MARKET.md`,
`docs/mercury/PARTNERSHIP_STRATEGY.md`,
`docs/mercury/epics/MASTER_PROJECT.md`, and
`docs/mercury/epics/PHASE_4_5_TICKETS.md` define the first post-bridge
expansion track as one downstream evidence-consumer path with reviewer-facing
assurance work.
**Current boundary references:** `.planning/v2.44-MILESTONE-AUDIT.md`,
`docs/mercury/SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md`,
`docs/mercury/SUPERVISED_LIVE_DECISION_RECORD.md`,
`docs/mercury/README.md`,
`crates/arc-mercury/src/main.rs`, and
`crates/arc-mercury/src/commands.rs` define the bounded reviewer package and
operator surface that downstream distribution must reuse rather than replace.
**Execution dependency note:** This milestone starts only after `v2.44`
closes the same-workflow supervised-live bridge. Phases `189` through `192`
must keep expansion limited to one downstream archive/review/case-management
consumer path, prefer evidence consumption over deep runtime coupling, and
avoid widening into OEM, trust-network, or multi-connector programs.

- [x] **DOWN-01**: MERCURY selects and freezes one downstream archive, review,
  or case-management consumer path for the next expansion step rather than
  starting multiple connector programs at once.
- [x] **DOWN-02**: MERCURY can generate one downstream distribution package
  profile rooted in the existing `Proof Package v1`, `Inquiry Package v1`, and
  supervised-live reviewer artifacts without redefining ARC truth.
- [x] **DOWN-03**: MERCURY can deliver that package through one bounded
  downstream export path with explicit acknowledgement, disclosure, and
  fail-closed error semantics.
- [x] **DOWN-04**: Reviewer-facing assurance packages and validation flows
  support internal and external review over the same underlying artifacts and
  the selected downstream consumer path.
- [x] **DOWN-05**: The expansion milestone ends with one explicit owner,
  operating model, and next-step boundary rather than implicit governance,
  OEM, or runtime-coupling sprawl.

### v2.44 MERCURY Supervised-Live Bridge and Controlled Productionization

**Research basis:** `docs/mercury/SUPERVISED_LIVE_BRIDGE.md`,
`docs/mercury/IMPLEMENTATION_ROADMAP.md`,
`docs/mercury/TECHNICAL_ARCHITECTURE.md`,
`docs/mercury/POC_DESIGN.md`, and `docs/mercury/GO_TO_MARKET.md` define the
preferred next step after pilot readiness and explicitly constrain it to the
same workflow before broader expansion tracks.
**Current boundary references:** `.planning/v2.43-MILESTONE-AUDIT.md`,
`docs/mercury/PILOT_RUNBOOK.md`,
`docs/mercury/EVALUATOR_VERIFICATION_FLOW.md`,
`docs/mercury/SUPERVISED_LIVE_BRIDGE.md`,
`crates/arc-mercury/src/main.rs`, and
`crates/arc-mercury-core/src/pilot.rs` define the current pilot-ready
workflow, proof contract, and operator surface that the supervised-live bridge
must preserve.
**Execution dependency note:** This milestone starts only after `v2.43`
proves the same workflow end to end. Phases `185` through `188` must keep the
same workflow family, keep existing customer execution systems primary, and
avoid broad connector or expansion programs.

- [x] **SLIVE-01**: The supervised-live bridge stays limited to the same
  controlled release, rollback, and inquiry workflow rather than widening into
  multiple workflows or generic integration programs.
- [x] **SLIVE-02**: MERCURY can ingest live or mirrored workflow events for
  that same workflow and bind them into the existing ARC/MERCURY proof and
  inquiry contracts without redefining truth.
- [x] **SLIVE-03**: Approval, interruption, rollback, and degraded-mode
  controls are explicit, auditable, and fail-closed for supervised-live
  operation.
- [x] **SLIVE-04**: Key management, monitoring, publication, retention, and
  operator runbooks are executable enough for controlled production review with
  a design partner.
- [x] **SLIVE-05**: The bridge ends with one explicit decision artifact:
  proceed to supervised-live, remain in replay/shadow, or stop without
  widening scope.

### v2.43 MERCURY Evidence Productization Foundation

**Research basis:** `docs/mercury/PRODUCT_BRIEF.md`,
`docs/mercury/TECHNICAL_ARCHITECTURE.md`,
`docs/mercury/IMPLEMENTATION_ROADMAP.md`,
`docs/mercury/PHASE_0_1_BUILD_CHECKLIST.md`, and
`docs/mercury/ARC_MODULE_MAPPING.md` define the product wedge, proof
boundary, build order, and ARC reuse posture.
**Current boundary references:** `docs/STRATEGIC_ROADMAP.md`,
`crates/arc-core/src/receipt.rs`,
`crates/arc-kernel/src/evidence_export.rs`,
`crates/arc-store-sqlite/src/receipt_store.rs`, and
`crates/arc-control-plane/src/lib.rs` plus `crates/arc-cli/src/evidence_export.rs`
define the existing ARC substrate that MERCURY must reuse rather than fork.
**Execution dependency note:** Phase `181` freezes the first supported workflow
and ARC reuse map. Phases `182` through `184` should be planned and executed
only after that scope lock is accepted.

- [x] **MERC-01**: MERCURY reuses ARC's signed receipt, checkpoint, evidence
  export, and verification substrate rather than inventing a separate truth
  contract for Phase 0-1.
- [x] **MERC-02**: MERCURY defines typed workflow evidence metadata covering
  business identifiers, chronology/causality, provenance, sensitivity, and
  disclosure state for one governed workflow.
- [x] **MERC-03**: MERCURY persists and queries its primary workflow/business
  identifiers through extracted indexed storage rather than production JSON
  scans over raw receipt blobs.
- [x] **MERC-04**: MERCURY ships `Proof Package v1`, `Publication Profile v1`,
  and `Inquiry Package v1` as portable contracts layered on top of ARC truth.
- [x] **MERC-05**: MERCURY can replay or shadow one controlled release,
  rollback, and inquiry workflow end to end with verifier-capable proof
  output.
- [x] **MERC-06**: ARC/MERCURY portfolio positioning, pilot materials, and
  external messaging remain explicit that ARC is the platform and MERCURY is
  the finance-specific product wedge.

### v2.10 Underwriting and Risk Decisioning

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` explicitly pushes from
receipt volume and reputation toward runtime underwriting, agent credit, and
liability-market primitives.
**Current boundary references:** `spec/PROTOCOL.md` explicitly says the
behavioral feed is a truthful evidence export rather than an underwriting
model, so this milestone is where that product boundary would intentionally
change.

- [x] **UW-01**: ARC defines signed underwriting-policy inputs and a stable risk
  taxonomy over receipts, reputation, certification, runtime assurance, and
  payment-side evidence.
- [x] **UW-02**: ARC can make bounded runtime decisions that approve, deny,
  step-up, or reduce economic ceilings using canonical evidence rather than
  ad hoc partner logic.
- [x] **UW-03**: Underwriting outputs remain explicit signed decision artifacts
  separate from canonical execution receipts.
- [x] **UW-04**: Operators can simulate, inspect, explain, and audit underwriting
  decisions before and after deployment.
- [x] **UW-05**: Qualification, partner proof, and release docs make clear that
  ARC now ships underwriting decisioning rather than only insurer-facing
  evidence export.

### v2.11 Portable Credential Interop and Wallet Distribution

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` calls for stronger VC,
OID4VCI, and broader wallet/verifier portability around the passport layer.
**Current boundary references:** `crates/arc-credentials/src/lib.rs` still
describes the credential format as intentionally simple and ARC-native,
`docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` excludes global trust registry
and public wallet distribution semantics today, and `spec/PROTOCOL.md` notes
that automatic portable-wallet distribution is not yet shipped.

- [x] **VC-01**: ARC supports at least one interoperable credential-issuance flow
  aligned with external VC ecosystem expectations rather than only ARC-native
  file and API delivery.
- [x] **VC-02**: Credential status, revocation, and supersession semantics are
  portable to wallet and verifier ecosystems without weakening current trust
  boundaries.
- [x] **VC-03**: ARC defines holder-facing presentation and transport semantics
  beyond direct file exchange so wallets and remote relying parties can use the
  passport layer cleanly.
- [x] **VC-04**: ARC ships compatibility qualification against at least one
  external wallet or verifier path.
- [x] **VC-05**: Broader credential interop preserves ARC's conservative rules
  against synthetic global trust, silent federation, and authority widening.

### v2.12 Workload Identity and Attestation Verification Bridges

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` points to SPIFFE/SVID,
RATS-style attestation evidence, and stronger workload identity as the bridge
between agent trust and runtime environment truth.
**Current boundary references:** `crates/arc-core/src/lib.rs` currently treats
SPIFFE-like agent identifiers as opaque strings, `crates/arc-core/src/capability.rs`
normalizes runtime attestation evidence without shipping a full verifier stack,
and `docs/A2A_ADAPTER_GUIDE.md` shows mutual TLS support on the A2A edge rather
than a complete workload-identity substrate.

- [x] **ATTEST-01**: ARC can bind SPIFFE/SVID or equivalent workload identifiers to
  ARC runtime identity and policy decisions through explicit mapping rules.
- [x] **ATTEST-02**: ARC ships at least one concrete cloud or vendor attestation
  verifier bridge instead of relying only on opaque normalized evidence input.
- [x] **ATTEST-03**: Attestation trust policy is operator-configurable, fail-closed,
  and explicit about verifier identity, validity, and acceptable evidence
  classes.
- [x] **ATTEST-04**: Workload-identity and attestation bridges can narrow or widen
  rights only through explicit policy rather than implicit runtime metadata.
- [x] **ATTEST-05**: Qualification and operator runbooks cover verifier failure
  modes, replay boundaries, and cross-system trust semantics.

### v2.13 Portable Credential Format and Lifecycle Convergence

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` calls for portable
credentials, broader VC compatibility, and wallet-mediated portability beyond
ARC-native artifacts.
**Current boundary references:** `docs/CREDENTIAL_INTEROP_GUIDE.md`,
`docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`, and
`.planning/research/PORTABLE_CREDENTIAL_PORTABILITY_PLAN_POST_V2.12.md`
describe the currently missing SD-JWT VC path, portable status semantics, and
research-driven closure strategy.

- [x] **PVC-01**: ARC issues at least one standards-native portable credential
  format in addition to `arc-agent-passport+json`.
- [x] **PVC-02**: Selective disclosure is explicit, policy-bounded, and
  verifier-request-driven rather than ad hoc field filtering.
- [x] **PVC-03**: Portable type metadata, issuer metadata, and signing-key
  material are published at stable HTTPS locations with integrity rules.
- [x] **PVC-04**: Status, revocation, and supersession map from ARC operator truth
  into portable verifier semantics without inventing a new trust root.
- [x] **PVC-05**: ARC-native passport and federation flows remain supported and
  fail closed when external-format requests are unsupported.

### v2.14 OID4VP Verifier and Wallet Interop

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` positions passports as
cross-org portability artifacts, which requires a real verifier-side transport
and presentation path rather than ARC-native challenge exchange alone.
**Current boundary references:** `docs/CREDENTIAL_INTEROP_GUIDE.md`,
`spec/PROTOCOL.md`, and
`.planning/research/PORTABLE_CREDENTIAL_PORTABILITY_PLAN_POST_V2.12.md`
document the shipped narrow verifier-side OID4VP path and the explicit
boundaries that remain out of scope.

- [x] **PVP-01**: ARC can act as an OID4VP verifier for the ARC SD-JWT VC profile.
- [x] **PVP-02**: ARC supports one pragmatic verifier-authentication profile
  suitable for public verifier deployment.
- [x] **PVP-03**: ARC supports same-device and cross-device wallet invocation
  without requiring proprietary ARC holder transport.
- [x] **PVP-04**: At least one external wallet path passes issuance, presentation,
  selective disclosure, and status validation end to end.
- [x] **PVP-05**: Unsupported ecosystems such as DIDComm, global wallet
  directories, and synthetic trust registries remain explicit non-goals.

### v2.15 Multi-Cloud Attestation and Appraisal Contracts

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` points toward SPIFFE,
RATS, EAT, and cloud-attestation ecosystems as inputs into bounded trust
decisions.
**Current boundary references:** `docs/WORKLOAD_IDENTITY_RUNBOOK.md`,
`docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`, and the workload-attestation
planner output from agent research identify Azure-first bridging as only the
first step.

- [x] **RATS-01**: ARC supports at least two additional concrete verifier paths
  beyond Azure, covering materially different attestation families.
- [x] **RATS-02**: ARC defines one typed appraisal contract that separates raw
  evidence, verifier identity, normalized assertions, and vendor-scoped
  claims.
- [x] **RATS-03**: ARC documents and enforces a conservative normalization
  boundary rather than pretending vendor claims are globally equivalent.
- [x] **RATS-04**: Trusted-verifier policy evolves into adapter-aware appraisal
  rules without silently widening runtime trust.
- [x] **RATS-05**: ARC emits one signed appraisal or export artifact aligned with
  EAT or attestation-result semantics without overclaiming generic
  interoperability.
- [x] **RATS-06**: Appraised runtime evidence influences issuance, governed
  execution, and underwriting through explicit policy and reason codes.
- [x] **RATS-07**: Qualification proves replay, freshness, rotation, debug, and
  measurement-boundary behavior across multiple verifier families.

### v2.16 Enterprise Authorization and IAM Standards Profiles

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` frames rights as an
intersection of capabilities and OAuth-family authorization details, with
transaction context and sender-constrained semantics as key external
legibility surfaces.
**Current boundary references:** `docs/ECONOMIC_INTEROP_GUIDE.md`,
`docs/standards/ARC_OAUTH_AUTHORIZATION_PROFILE.md`,
`docs/release/QUALIFICATION.md`, and `spec/PROTOCOL.md` now define the
normative profile, sender-constrained discovery boundary, machine-readable
metadata, reviewer packs, and conformance proof surface.

- [x] **IAM-01**: ARC publishes one normative authorization semantics profile that
  maps governed actions into richer authorization details and transaction
  context without introducing a second mutable auth truth.
- [x] **IAM-02**: ARC makes sender-constrained and assurance-bound semantics
  legible for enterprise IAM reviewers.
- [x] **IAM-03**: External reviewers can trace a governed action from intent and
  approval through projected auth context into signed receipt truth.
- [x] **IAM-04**: ARC exposes machine-readable discovery, metadata, or equivalent
  profile artifacts sufficient for enterprise integration review.
- [x] **IAM-05**: Qualification proves fail-closed behavior for mismatched auth
  context, missing intent binding, stale assurance data, and delegated
  call-chain mismatch.

### v2.17 ARC Certify Public Discovery Marketplace and Governance

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` positions certification
and registry fees as a marketplace primitive and part of the trust substrate
for agent ecosystems.
**Current boundary references:** `spec/PROTOCOL.md`, `docs/release/RELEASE_CANDIDATE.md`,
and the marketplace planner output all state that today's certification
surface is intentionally operator-scoped rather than public-marketplace grade.

- [x] **CERT-01**: ARC Certify has versioned, reproducible certification criteria
  and evidence packages that independent operators can publish and consumers
  can compare.
- [x] **CERT-02**: Public certification discovery is searchable and comparable
  across operators while preserving publisher provenance and state.
- [x] **CERT-03**: Marketplace presence never auto-grants runtime trust; consumer
  admission remains policy-controlled and evidence-backed.
- [x] **CERT-04**: Revocation, supersession, dispute, and evidence updates are
  publicly visible and auditable.
- [x] **CERT-05**: Qualification proves a public publish, discover, resolve, and
  consume flow end to end with explicit governance boundaries.

### v2.18 Credit, Exposure, and Capital Policy

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` explicitly sequences
receipt volume and underwriting into agent credit and bounded capital
allocation.
**Current boundary references:** `docs/release/RELEASE_CANDIDATE.md`,
`spec/PROTOCOL.md`, and
`.planning/research/POST_V2_12_ECONOMIC_MARKET_ENDGAME.md` document the
current stop at underwriting and the proposed credit-grade next layer.

- [x] **CREDIT-01**: ARC defines one canonical exposure ledger and signed exposure
  artifact over governed actions, premiums, reserves, losses, recoveries, and
  settlement state.
- [x] **CREDIT-02**: ARC produces a versioned, explainable credit scorecard with
  explicit probation and anomaly semantics.
- [x] **CREDIT-03**: ARC issues signed capital-facility policies that allocate
  bounded capital based on score, exposure, assurance, and certification.
- [x] **CREDIT-04**: ARC ships backtests, simulation, and a provider-facing risk
  package sufficient for external capital review.

### v2.19 Bonded Autonomy and Facility Execution

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` explicitly names bonded
agents and staking-like market discipline as a later but central part of the
endgame.
**Current boundary references:** `.planning/research/POST_V2_12_ECONOMIC_MARKET_ENDGAME.md`
and `docs/AGENT_REPUTATION.md` provide the best current design basis for
reserve and delegation-bond semantics.

- [x] **BOND-01**: ARC defines signed bond, reserve, collateral, and slash or
  release artifacts with explicit lifecycle state.
- [x] **BOND-02**: Economically sensitive autonomy tiers fail closed when bond,
  reserve, or assurance prerequisites are missing.
- [x] **BOND-03**: Loss, delinquency, recovery, reserve-release, and write-off
  state is immutable and auditable.
- [x] **BOND-04**: Bonded execution is qualification-backed with simulation,
  operator controls, and one external-capital adapter proof.

### v2.20 Liability Marketplace and Claims Network

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` calls the
liability-market endgame the strongest long-run expression of ARC's economic
security thesis.
**Current boundary references:** `.planning/research/POST_V2_12_ECONOMIC_MARKET_ENDGAME.md`,
`docs/release/RELEASE_CANDIDATE.md`, and `spec/PROTOCOL.md` all make clear
that current ARC stops short of quote, bind, and claim orchestration.

- [x] **MARKET-01**: ARC exposes a curated provider registry with supported
  jurisdictions, evidence requirements, currencies, and coverage classes.
- [x] **MARKET-02**: ARC defines canonical quote-request, quote-response,
  placement, and bound-coverage artifacts over one risk package.
- [x] **MARKET-03**: ARC defines immutable claim packages, provider responses,
  dispute state, and adjudication evidence linked back to receipts and
  exposure artifacts.
- [x] **MARKET-04**: Qualification proves a multi-provider quote, placement,
  claim, and dispute flow end to end and updates the public product boundary
  honestly.

### v2.21 Standards-Native Authorization and Credential Fabric

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` treats portable
identity, transaction context, and standards-legible rights as part of the
same end-state rather than separate reporting layers.
**Current boundary references:** `spec/PROTOCOL.md`,
`docs/release/RELEASE_CANDIDATE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` make clear that
current ARC still splits narrow portable credential projections from
request-time hosted authorization semantics.

- [x] **STDFAB-01**: ARC supports a bounded portable claim catalog and more than
  one standards-legible credential profile over one canonical passport truth.
- [x] **STDFAB-02**: ARC defines portable issuer and subject binding rules that
  preserve `did:arc` provenance without forcing one global subject identifier
  model.
- [x] **STDFAB-03**: Governed intent, approval truth, and request-time hosted
  authorization semantics align in one bounded standards-facing contract.
- [x] **STDFAB-04**: Portable status, revocation, supersession, and metadata
  surfaces converge with hosted metadata and fail closed on drift.
- [x] **STDFAB-05**: Unsupported format, binding, metadata, or auth-context
  combinations are explicit failures and qualification-backed.

### v2.22 Wallet Exchange, Identity Assertions, and Sender-Constrained Authorization

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` implies a broader wallet
and authorization ecosystem than ARC's current one-request-object bridge.
**Current boundary references:** `docs/CREDENTIAL_INTEROP_GUIDE.md`,
`docs/standards/ARC_OAUTH_AUTHORIZATION_PROFILE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` all describe the
remaining wallet, identity assertion, and live sender-constrained gap.

- [x] **WALLETX-01**: ARC defines one transport-neutral wallet exchange model
  with canonical replay-safe verifier transaction state.
- [x] **WALLETX-02**: ARC supports one optional identity-assertion lane for
  holder session continuity or verifier login without making it mandatory for
  every presentation.
- [x] **WALLETX-03**: ARC supports a bounded live sender-constrained contract
  over DPoP and mTLS with explicit proof continuity rules.
- [x] **WALLETX-04**: Attestation-bound sender semantics, if exposed, remain
  explicitly bounded and do not widen execution authority from attestation
  alone.
- [x] **WALLETX-05**: Qualification covers same-device, cross-device, and one
  asynchronous or message-oriented exchange path plus sender-constrained
  negative cases.

### v2.23 Common Appraisal Vocabulary and External Result Interop

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` points toward RATS/EAT-
like role separation and verifier semantics, not only internal adapter output.
**Current boundary references:** `docs/WORKLOAD_IDENTITY_RUNBOOK.md`,
`docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` define the current
bounded Azure/AWS/Google appraisal bridge and the remaining external-result
gap.

- [x] **APPX-01**: ARC defines one versioned common appraisal contract that
  separates evidence identity, normalized claims, vendor claims, verifier
  statement, provenance inputs, and local ARC policy outcome.
- [x] **APPX-02**: ARC defines one versioned normalized claim vocabulary and
  reason taxonomy that more than one verifier family can emit.
- [x] **APPX-03**: ARC can export and import signed appraisal results while
  keeping external verifier provenance and local policy decision separate.
- [x] **APPX-04**: Existing Azure, AWS, and Google bridges remain backward-
  compatible and fail closed during the common-contract migration.
- [x] **APPX-05**: Qualification proves mixed-provider portability and honest
  documentation boundaries for external appraisal-result interop.

### v2.24 Verifier Federation, Cross-Issuer Portability, and Discovery

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` implies cross-issuer
portability, broader verifier ecosystems, and public discovery layers as part
of the open trust substrate.
**Current boundary references:** `docs/CREDENTIAL_INTEROP_GUIDE.md`,
`docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` describe the gap
between today's bounded bridges and a federated, discovery-capable substrate.

- [x] **FEDX-01**: ARC supports cross-issuer portfolios, trust packs, and
  migration or supersession semantics without inventing synthetic global trust.
- [x] **FEDX-02**: ARC defines verifier descriptors, trust bundles, and
  endorsement or reference-value distribution with provenance and rotation
  semantics.
- [x] **FEDX-03**: ARC publishes public issuer and verifier discovery surfaces
  with transparency and explicit local import policy.
- [x] **FEDX-04**: ARC supports additional provider or verifier families on the
  same common appraisal contract and portable identity substrate.
- [x] **FEDX-05**: Discovery and federation never auto-admit runtime trust;
  local policy activation remains explicit and auditable.

### v2.25 Live Capital Allocation and Escrow Execution

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` pushes from underwriting
and credit into actual agent credit allocation and capital-backed autonomy.
**Current boundary references:** `spec/PROTOCOL.md`,
`docs/release/RELEASE_CANDIDATE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` all make clear that
ARC currently stops at bounded facility and bond policy rather than live
capital execution.

- [x] **CAPX-01**: ARC defines live capital-book and source-of-funds artifacts
  with explicit committed, held, drawn, disbursed, released, repaid, and
  impaired state.
- [x] **CAPX-02**: ARC defines custody-neutral escrow or reserve instruction
  artifacts with separate intended and externally reconciled state.
- [x] **CAPX-03**: Governed actions can be mapped to one explicit source of
  funds and allocation decision under bounded policy.
- [x] **CAPX-04**: Regulated roles, authority chains, and execution windows are
  explicit whenever ARC starts moving or locking live capital.
- [x] **CAPX-05**: Live capital execution remains simulation-first and fail
  closed on mixed-currency, missing-counterparty, or reconciliation mismatch
  conditions.

### v2.26 Reserve Control, Autonomous Pricing, and Claims Payment

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` goes beyond credit and
bounded liability artifacts into bonded autonomy, pricing, coverage, and
market-backed loss handling.
**Current boundary references:** `spec/PROTOCOL.md`,
`docs/release/RELEASE_CANDIDATE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` define the current
boundary after reserve control, auto-bind, bounded automatic claims payment,
and bounded recovery-clearing posture.

- [x] **LIVEX-01**: ARC can execute reserve impairment, release, and slash
  controls under explicit evidence, appeal, and reconciliation rules.
- [x] **LIVEX-02**: ARC supports delegated pricing authority and automatic
  coverage binding only inside one explicit provider or regulated-role envelope.
- [x] **LIVEX-03**: ARC supports a narrow automatic claims-payment lane with
  payout instructions, payout receipts, and external reconciliation artifacts.
- [x] **LIVEX-04**: ARC can clear recoveries, reinsurance obligations, or
  facility reimbursements across counterparties without hidden state.
- [x] **LIVEX-05**: Every live-money transition is explicitly role-attributed,
  evidence-linked, and fail closed on counterparty mismatch or stale authority.

### v2.27 Open Registry, Trust Activation, and Governance Network

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` points toward broader
registry, governance, and market-discipline structure, not only curated
discovery.
**Current boundary references:** `spec/PROTOCOL.md`,
`docs/release/RELEASE_CANDIDATE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` all keep today's
discovery surfaces public-but-curated and non-auto-trusting.

- [x] **OPENX-01**: ARC defines a generic listing and namespace model for tools,
  issuers, verifiers, providers, and future market actors.
- [x] **OPENX-02**: Origin operators, mirrors, indexers, ranked search, and
  freshness metadata are explicit and reproducible.
- [x] **OPENX-03**: ARC defines trust-activation artifacts and open admission
  classes so visibility never equals runtime admission.
- [x] **OPENX-04**: Governance charters, dispute escalation, sanctions, freezes,
  and appeals can travel across operators with signed case artifacts.
- [x] **OPENX-05**: Open publish lanes remain bounded by economics, identity, or
  bond requirements and fail closed under abuse or unverifiable evidence.

### v2.28 Portable Reputation, Marketplace Economics, and Endgame Qualification

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` treats the final market
thesis as one governed ecosystem with portable evidence, market discipline, and
liability or abuse controls rather than a universal trust oracle.
**Current boundary references:** `.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md`
and `docs/release/RELEASE_CANDIDATE.md` define the remaining gap between
today's bounded control plane and the full open-market endgame claim.

- [x] **ENDX-01**: ARC supports portable reputation and negative-event exchange
  with issuer provenance and local weighting rather than a global trust score.
- [x] **ENDX-02**: ARC defines marketplace fee schedules, publisher or dispute
  bonds, slashing, and abuse-resistance economics.
- [x] **ENDX-03**: Qualification proves adversarial multi-operator open-market
  behavior without collapsing visibility into trust.
- [x] **ENDX-04**: Partner proof, release audit, and protocol docs are updated
  to claim the widened endgame honestly and explicitly.
- [x] **ENDX-05**: ARC still preserves explicit non-goals against universal
  trust oracles, automatic cross-issuer scores, and ambient trust widening.

### Post-v2.28 Maximal Endgame Ladder (Planned Only)

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` can be read more
aggressively than ARC's current bounded claim: real capital movement,
autonomous insurer-like pricing, more open trust-market formation, and broader
public identity or wallet interoperability.
**Current boundary references:** `docs/release/RELEASE_CANDIDATE.md`,
`spec/PROTOCOL.md`, and
`.planning/research/POST_V2_28_MAXIMAL_ENDGAME_ROADMAP.md` define the current
explicit non-goals and the activated post-`v2.28` maximal-endgame ladder.

- [x] **EXTMAX-01**: ARC defines named extension points with an explicit split
  between canonical truth surfaces and replaceable adapters or providers.
- [x] **EXTMAX-02**: ARC ships one official stack package over first-party
  implementations while preserving compatibility for custom extension
  implementations.
- [x] **EXTMAX-03**: Extension manifests, capability negotiation, versioning,
  and compatibility rules are machine-readable and fail closed on mismatch.
- [x] **EXTMAX-04**: Extensions cannot silently widen trust, mutate signed
  truth, or bypass local policy activation even when they supply external
  evidence or execution.
- [x] **EXTMAX-05**: Qualification proves custom extension implementations can
  interoperate with the official ARC stack without weakening the trust
  boundary.

- [x] **RAILMAX-01**: ARC can execute approved capital, reserve, payout, and
  settlement actions over at least one real external rail adapter rather than
  only issue neutral instruction artifacts.
- [x] **RAILMAX-02**: External settlement proofs reconcile back to canonical ARC
  receipts, claims, and capital state without mutating prior signed truth.
- [x] **RAILMAX-03**: Chargebacks, reversals, partial settlements, and rail
  failures are explicit lifecycle states rather than undocumented exceptions.
- [x] **RAILMAX-04**: Regulated-role and custody boundaries remain explicit even
  when ARC can trigger real external movement.
- [x] **RAILMAX-05**: Qualification proves end-to-end rail dispatch, reversal,
  and recovery behavior against at least one real or certified test rail.

- [x] **INSMAX-01**: ARC can compute bounded autonomous pricing decisions from
  underwriting, reputation, loss, assurance, and capital evidence rather than
  relying only on delegated manual envelopes.
- [x] **INSMAX-02**: ARC can optimize reserve and capital allocation across
  facilities, quotes, and claims through explicit model-governed policy.
- [x] **INSMAX-03**: Automatic reprice, renew, decline, and bind execution can
  occur within explicit authority envelopes and rollback controls.
- [x] **INSMAX-04**: Operators can simulate, explain, compare, and override
  autonomous pricing and allocation decisions before or after deployment.
- [x] **INSMAX-05**: Qualification proves drift detection, rollback, and
  fail-closed safe-state behavior for autonomous insurance automation.

- [x] **TRUSTMAX-01**: ARC can express cross-operator trust activation or
  federation contracts rather than only local operator activation.
- [x] **TRUSTMAX-02**: Mirror and indexer publication can participate in
  verifiable federation state with explicit quorum, conflict, and anti-eclipse
  semantics.
- [x] **TRUSTMAX-03**: ARC supports bounded open-admission or stake/bond
  participation classes without collapsing into ambient runtime trust.
- [x] **TRUSTMAX-04**: Portable reputation and negative-event exchange can flow
  through a shared clearing model across operators with explicit anti-sybil and
  anti-oracle controls.
- [x] **TRUSTMAX-05**: Qualification proves adversarial cross-operator
  federation behavior under conflicting trust, hostile publishers, and shared
  reputation abuse.

- [x] **IDMAX-01**: ARC supports broader DID/VC method and credential-family
  interoperability than the current bounded ARC-first public profile.
- [x] **IDMAX-02**: ARC supports public wallet directory, routing, or equivalent
  ecosystem discovery semantics without silently widening trust.
- [x] **IDMAX-03**: Multi-wallet, multi-issuer, and cross-operator presentation
  flows are qualified end to end across the supported identity network.
- [x] **IDMAX-04**: ARC's public identity and wallet surface remains explicit
  about trust, issuer, and admission boundaries even after broadening
  compatibility.
- [x] **IDMAX-05**: Partner proof, release audit, and protocol docs can claim
  the strongest plausible reading of the research thesis honestly and
  specifically.

### v2.34 Official Web3 Runtime Contracts and Deployment Harness

**Research basis:** `docs/research/ARC_WEB3_CONTRACT_ARCHITECTURE.md`,
`docs/research/ARC_WEB3_TRUST_BOUNDARY_DECISIONS.md`, and
`docs/standards/ARC_WEB3_CONTRACT_PACKAGE.json` define the official runtime
contract family and its trust-boundary assumptions.
**Current boundary references:** `contracts/`, `crates/arc-web3-bindings/`,
`docs/standards/ARC_WEB3_PROFILE.md`, and `spec/PROTOCOL.md` now describe the
shipped local runtime-contract package and its bounded release posture.

- [x] **W3STACK-01**: ARC ships compilable Solidity reference contracts for the
  root registry, escrow, bond vault, identity registry, and price resolver
  that match the frozen official interfaces.
- [x] **W3STACK-02**: Deployment manifests, generated bindings, and local
  devnet/test harnesses are reproducible across the official Base-first and
  Arbitrum-secondary topology.
- [x] **W3STACK-03**: Contract events, nonces, sequence numbers, and state
  transitions reconcile deterministically with ARC's signed artifact model.
- [x] **W3STACK-04**: Gas limits, storage layout, admin or pause powers,
  immutability, and upgrade assumptions are explicit, tested, and reviewable.
- [x] **W3STACK-05**: Qualification proves parity between Solidity contracts,
  generated bindings, Rust artifact types, and published standards examples.

### v2.35 arc-link Oracle Runtime and Cross-Currency Budget Enforcement

**Research basis:** `docs/research/ARC_LINK_RESEARCH.md` defines `arc-link v1`
as the off-chain oracle runtime for cross-currency budget enforcement, while
`docs/research/ARC_LINK_FUTURE_TRACKS.md` explicitly parks adjacent features
for later milestones.
**Current boundary references:** `docs/standards/ARC_WEB3_PROFILE.md` and
`crates/arc-core/src/web3.rs` already model oracle evidence, but ARC does not
yet ship a real Chainlink/Pyth client, feed policy, or runtime budget gate.

- [x] **LINKX-01**: `arc-link` can read Chainlink feeds via Alloy with explicit
  decimal normalization, staleness checks, heartbeat rules, and Base-first
  operator configuration.
- [x] **LINKX-02**: ARC can enforce cross-currency budgets using explicit
  oracle-evidence side artifacts without mutating canonical receipt truth.
- [x] **LINKX-03**: Multi-oracle fallback, TWAP smoothing, and divergence
  detection exist so feed outages or manipulations fail closed rather than
  silently widening spend.
- [x] **LINKX-04**: Operator controls cover feed address pinning, cache policy,
  outage handling, and circuit-breaker thresholds.
- [x] **LINKX-05**: Qualification proves allow or deny behavior under stale,
  divergent, manipulated, missing, or chain-mismatched oracle inputs.

### v2.36 arc-anchor Multi-Chain Anchoring and Proof Verification

**Research basis:** `docs/research/ARC_ANCHOR_RESEARCH.md` defines
`arc-anchor` as a multi-chain anchoring service over EVM/L2, Bitcoin
OpenTimestamps, and Solana.
**Current boundary references:** `crates/arc-anchor/src/lib.rs`,
`docs/standards/ARC_ANCHOR_PROFILE.md`, and the `ARC_ANCHOR_*` standards
artifacts now define ARC's bounded publication, imported-proof, discovery, and
qualification surface.

- [x] **ANCHORX-01**: `arc-anchor` can publish checkpoint Merkle roots to the
  official Base/Arbitrum root-registry contracts and verify inclusion proofs
  back to canonical ARC checkpoints.
- [x] **ANCHORX-02**: Bitcoin OpenTimestamps secondary anchoring is supported
  with verifiable linkage from ARC checkpoint statements to Bitcoin proofs.
- [x] **ANCHORX-03**: Solana anchoring is supported and normalized into the
  same proof-bundle semantics as the EVM and Bitcoin lanes.
- [x] **ANCHORX-04**: Verifier discovery, operator identity binding, proof-
  bundle packaging, and root-publication ownership remain explicit and
  fail-closed.
- [x] **ANCHORX-05**: Qualification proves publication, replay/reorg recovery,
  and independent third-party verification across the supported anchor lanes.

### v2.37 arc-settle On-Chain Settlement, Escrow, and Bond Runtime

**Research basis:** `docs/research/ARC_SETTLE_RESEARCH.md` and
`docs/research/ARC_SETTLE_PROTOCOL_DECISIONS.md` define `arc-settle`,
settlement evidence formats, dispute policy, bond lifecycle, and failure
recovery over the web3 contract stack.
**Current boundary references:** `docs/standards/ARC_SETTLE_PROFILE.md`,
`docs/standards/ARC_SETTLE_QUALIFICATION_MATRIX.json`, and
`docs/release/ARC_SETTLE_RUNBOOK.md` now define ARC's bounded settlement
runtime over the official contract family.

- [x] **SETTLEX-01**: `arc-settle` can translate approved capital instructions
  into real escrow, release, refund, slash, and settlement transactions over
  the official contract family.
- [x] **SETTLEX-02**: Settlement observation captures dispatch, finality,
  dispute windows, refund or reversal, partial settlement, timeout, reorg, and
  bond lifecycle state explicitly.
- [x] **SETTLEX-03**: Dual-signature and Merkle-proof settlement paths are both
  supported or explicitly qualified, with Solana-native Ed25519 verification
  used where that path is supported.
- [x] **SETTLEX-04**: Multi-chain consistency, failure recovery, custody
  boundaries, and regulated-role assumptions remain explicit in runtime and
  documentation.
- [x] **SETTLEX-05**: Qualification proves end-to-end settlement on local/test
  rails plus failure, reorg, timeout, and dispute recovery paths.

### v2.38 Web3 Automation, Cross-Chain Transport, and Agent Payment Interop

**Research basis:** `docs/research/ARC_LINK_FUTURE_TRACKS.md` explicitly
captures the parked CCIP, Chainlink Functions, Chainlink Automation, x402, and
ecosystem-payment tracks that were left out of `v2.30`.
**Current boundary references:** `docs/standards/ARC_FUNCTIONS_FALLBACK_PROFILE.md`,
`docs/standards/ARC_AUTOMATION_PROFILE.md`,
`docs/standards/ARC_CCIP_PROFILE.md`, and
`docs/standards/ARC_PAYMENT_INTEROP_PROFILE.md` now define the shipped bounded
interop surface.

- [x] **WEBAUTO-01**: ARC supports at least one bounded EVM-side proof-
  verification path for Ed25519-constrained evidence, such as Chainlink
  Functions or an equivalent explicit fallback strategy.
- [x] **WEBAUTO-02**: Automation can schedule anchoring, settlement watchdog,
  timeout, and bond jobs without turning off-chain schedulers into ambient
  trust.
- [x] **WEBAUTO-03**: CCIP can transport bounded delegation or settlement-
  coordination messages with reconciliation back to canonical ARC truth.
- [x] **WEBAUTO-04**: ARC offers bounded compatibility with x402, Circle
  nanopayments, and ERC-4337/paymaster patterns where they improve machine
  payment and gas handling.
- [x] **WEBAUTO-05**: Qualification proves these automation and interoperability
  surfaces fail closed under DON outage, delayed messages, duplicate
  execution, or unsupported-chain conditions.

### v2.39 Web3 Production Qualification, Operations, and Public Claim Closure

**Research basis:** the late-March 2026 web3 papers collectively assume real
operator services, deployment, monitoring, and public claims rather than only
artifact modeling.
**Current boundary references:** `docs/release/RELEASE_CANDIDATE.md` and
`spec/PROTOCOL.md` still describe ARC's shipped web3 surface as one bounded
official lane rather than a complete runtime stack.

- [x] **W3OPS-01**: The web3 runtime stack has observability, indexers,
  reorg-handling, incident response, and pause/emergency controls sufficient
  for live operation.
- [x] **W3OPS-02**: Security review or audit findings, gas budgets, latency
  budgets, and deployment gating rules are tracked to explicit closure.
- [x] **W3OPS-03**: Promotion from local/devnet to testnet/mainnet is
  reproducible, policy-gated, and documented.
- [x] **W3OPS-04**: Partner proof and external qualification cover the full
  contract, oracle, anchor, settlement, and automation stack end to end.
- [x] **W3OPS-05**: Protocol, release, partner-proof, and standards documents
  are rewritten to claim only the runtime capabilities that actually exist.

### v2.40 Web3 Runtime Integrity, Evidence Gating, and Contract Coherence

**Research basis:** the post-`v2.39` review of the shipped stack surfaced
remaining correctness risk around settlement identity derivation, optional
checkpoint substrate wiring, reserve semantics, proof-bundle verification, and
oracle authority split.
**Current boundary references:** `.planning/v2.39-MILESTONE-AUDIT.md`,
`docs/release/ARC_WEB3_READINESS_AUDIT.md`, `docs/release/RELEASE_CANDIDATE.md`,
and `spec/PROTOCOL.md` describe the bounded web3 stack honestly but do not yet
eliminate those internal truth-coherence gaps.

- [x] **W3INT-01**: Escrow and bond identity remain truthful and concurrency-
  safe across dispatch, observation, retry, and recovery flows.
- [x] **W3INT-02**: Durable receipt storage and checkpoint issuance are
  mandatory prerequisites for web3-enabled lanes rather than optional kernel
  features.
- [x] **W3INT-03**: Bond reserve and collateral semantics are aligned across
  contracts, bindings, runtime code, and public docs.
- [x] **W3INT-04**: Proof-bundle verification cryptographically validates
  secondary lanes instead of accepting metadata presence alone.
- [x] **W3INT-05**: Oracle authority, contract bindings, runtime config, and
  standards artifacts share one canonical source of truth.

### v2.41 Hosted Qualification, Deployment Promotion, and Operator Controls

**Research basis:** ARC's own release and readiness docs still hold external
publication on hosted qualification, deployment-runner availability, generated
monitoring artifacts, and operator-real control exercises.
**Current boundary references:** `docs/release/ARC_WEB3_READINESS_AUDIT.md`,
`docs/release/ARC_WEB3_DEPLOYMENT_PROMOTION.md`,
`docs/standards/ARC_WEB3_DEPLOYMENT_POLICY.json`, and
`docs/release/RELEASE_CANDIDATE.md` all name these gates as unresolved.

- [x] **W3REL-01**: Hosted release qualification executes the bounded web3
  runtime lane and publishes its artifacts for the exact candidate commit.
- [x] **W3REL-02**: Promotion from reviewed manifests to real operator rollout
  is reproducible, approval-gated, and rollback-aware.
- [x] **W3REL-03**: Runtime monitoring evidence is generated from qualification
  and incident drills instead of relying only on example JSON.
- [x] **W3REL-04**: Emergency modes for `arc-link`, `arc-anchor`, and
  `arc-settle` are operator-exercisable, persisted, and auditable.
- [x] **W3REL-05**: Hosted qualification proves integrated recovery,
  dual-sign, FX-backed, and partner-reviewable end-to-end settlement behavior.

### v2.42 Release Truth, Planning Integrity, and Assurance Backfill

**Research basis:** the shipped stack now outpaces the authoritative release
governance docs, research-to-runtime bridges, planning automation, missing
Nyquist artifacts, and ownership boundaries that future work depends on.
**Current boundary references:** `.planning/v2.39-MILESTONE-AUDIT.md`,
`docs/release/RELEASE_AUDIT.md`, `docs/release/QUALIFICATION.md`,
`docs/release/PARTNER_PROOF.md`, `docs/release/GA_CHECKLIST.md`, and
`spec/PROTOCOL.md` show where that truth and sustainability drift remains.

- [x] **W3SUST-01**: Release governance, audit, and candidate-facing docs are
  authoritative for the current post-`v2.39` stack and hosted evidence model.
- [x] **W3SUST-02**: Protocol and standards docs enumerate the shipped artifact
  family accurately, while research docs clearly bridge to superseding runtime
  names and boundaries.
- [x] **W3SUST-03**: GSD planning and roadmap tooling return coherent results
  for repos with active, completed, and newly activated milestone ladders.
- [x] **W3SUST-04**: Nyquist validation and phase-artifact completeness are
  restored for the late web3 ladder so future audits can trust those signals.
- [x] **W3SUST-05**: Oversized runtime entrypoints are decomposed into clearer
  ownership boundaries without reintroducing dependency cycles or shell-heavy
  orchestration.

## Out of Scope

| Feature | Reason |
|---------|--------|
| ARC as a direct payment rail | ARC continues to bridge to payment rails and meter them truthfully rather than becoming a settlement network itself. |
| Synthetic universal trust oracle | Imported trust, portable reputation, and cross-issuer evidence remain provenance-preserving and locally weighted instead of collapsing into one global truth source. |
| Ambient runtime trust from discovery visibility | Even the planned open registry and discovery lanes must require explicit local trust activation and never treat visibility as admission. |
| Automatic authority widening from identity, attestation, or imported evidence | Enterprise identity, workload evidence, and federated artifacts may inform evaluation, but they must not silently expand rights, billing scope, or runtime trust. |
| ARC as an implicit regulated actor of record | Later milestones may orchestrate regulated-role execution profiles, but the role performing pricing, custody, claims payment, or collection must remain explicit rather than being assumed from generic ARC operation. |
| Permissionless operator discovery in the bounded v1 web3 lane | `ARC_WEB3_TRUST_BOUNDARY_DECISIONS.md` chose DID-service discovery plus canonical chain registries instead of ambient permissionless discovery; widening that trust model would need a separate product decision. |
| Chainlink BUILD program work as a roadmap phase | `ARC_LINK_FUTURE_TRACKS.md` classifies BUILD as business/BD rather than engineering implementation, so it is not tracked as an executable technical milestone. |
| External release publication from local evidence alone | Hosted `CI` and hosted `Release Qualification` observation remain required before public tagging or publication. |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| TRUST-01 | Phase 37 | Complete |
| TRUST-02 | Phase 38 | Complete |
| TRUST-03 | Phase 39 | Complete |
| TRUST-04 | Phase 40 | Complete |
| TRUST-05 | Phase 40 | Complete |
| RISK-01 | Phase 41 | Complete |
| RISK-02 | Phase 42 | Complete |
| RISK-03 | Phase 43 | Complete |
| RISK-04 | Phase 44 | Complete |
| RISK-05 | Phase 44 | Complete |
| EEI-01 | Phase 45 | Complete |
| EEI-02 | Phase 46 | Complete |
| EEI-03 | Phase 47 | Complete |
| EEI-04 | Phase 47 | Complete |
| EEI-05 | Phase 48 | Complete |
| UW-01 | Phase 49 | Complete |
| UW-02 | Phase 50 | Complete |
| UW-03 | Phase 51 | Complete |
| UW-04 | Phase 52 | Complete |
| UW-05 | Phase 52 | Complete |
| VC-01 | Phase 53 | Complete |
| VC-02 | Phase 54 | Complete |
| VC-03 | Phase 55 | Complete |
| VC-04 | Phase 56 | Complete |
| VC-05 | Phase 56 | Complete |
| ATTEST-01 | Phase 57 | Complete |
| ATTEST-02 | Phase 58 | Complete |
| ATTEST-03 | Phase 59 | Complete |
| ATTEST-04 | Phase 59 | Complete |
| ATTEST-05 | Phase 60 | Complete |
| PVC-01 | Phase 61 | Complete |
| PVC-02 | Phase 62 | Complete |
| PVC-03 | Phase 63 | Complete |
| PVC-04 | Phase 63 | Complete |
| PVC-05 | Phase 64 | Complete |
| PVP-01 | Phase 65 | Complete |
| PVP-02 | Phase 67 | Complete |
| PVP-03 | Phase 66 | Complete |
| PVP-04 | Phase 68 | Complete |
| PVP-05 | Phase 68 | Complete |
| RATS-01 | Phase 71 | Complete |
| RATS-02 | Phase 69 | Complete |
| RATS-03 | Phase 71 | Complete |
| RATS-04 | Phase 71 | Complete |
| RATS-05 | Phase 72 | Complete |
| RATS-06 | Phase 71 | Complete |
| RATS-07 | Phase 72 | Complete |
| IAM-01 | Phase 73 | Complete |
| IAM-02 | Phase 74 | Complete |
| IAM-03 | Phase 75 | Complete |
| IAM-04 | Phase 75 | Complete |
| IAM-05 | Phase 76 | Complete |
| CERT-01 | Phase 77 | Complete |
| CERT-02 | Phase 78 | Complete |
| CERT-03 | Phase 79 | Complete |
| CERT-04 | Phase 80 | Complete |
| CERT-05 | Phase 80 | Complete |
| CREDIT-01 | Phase 81 | Complete |
| CREDIT-02 | Phase 82 | Complete |
| CREDIT-03 | Phase 83 | Complete |
| CREDIT-04 | Phase 84 | Complete |
| BOND-01 | Phase 85 | Complete |
| BOND-02 | Phase 86 | Complete |
| BOND-03 | Phase 87 | Complete |
| BOND-04 | Phase 88 | Complete |
| MARKET-01 | Phase 89 | Complete |
| MARKET-02 | Phase 90 | Complete |
| MARKET-03 | Phase 91 | Complete |
| MARKET-04 | Phase 92 | Complete |
| STDFAB-01 | Phase 94 | Complete |
| STDFAB-02 | Phase 93 | Complete |
| STDFAB-03 | Phase 95 | Complete |
| STDFAB-04 | Phase 96 | Complete |
| STDFAB-05 | Phase 95 | Complete |
| WALLETX-01 | Phase 97 | Complete |
| WALLETX-02 | Phase 98 | Complete |
| WALLETX-03 | Phase 99 | Complete |
| WALLETX-04 | Phase 99 | Complete |
| WALLETX-05 | Phase 100 | Complete |
| APPX-01 | Phase 101 | Complete |
| APPX-02 | Phase 102 | Complete |
| APPX-03 | Phase 103 | Complete |
| APPX-04 | Phase 103 | Complete |
| APPX-05 | Phase 104 | Complete |
| FEDX-01 | Phase 105 | Complete |
| FEDX-02 | Phase 106 | Complete |
| FEDX-03 | Phase 107 | Complete |
| FEDX-04 | Phase 108 | Complete |
| FEDX-05 | Phase 107 | Complete |
| CAPX-01 | Phase 109 | Complete |
| CAPX-02 | Phase 110 | Complete |
| CAPX-03 | Phase 111 | Complete |
| CAPX-04 | Phase 112 | Complete |
| CAPX-05 | Phase 112 | Complete |
| LIVEX-01 | Phase 113 | Complete |
| LIVEX-02 | Phase 114 | Complete |
| LIVEX-03 | Phase 115 | Complete |
| LIVEX-04 | Phase 116 | Satisfied |
| LIVEX-05 | Phase 116 | Satisfied |
| OPENX-01 | Phase 117 | Complete |
| OPENX-02 | Phase 118 | Complete |
| OPENX-03 | Phase 119 | Complete |
| OPENX-04 | Phase 120 | Complete |
| OPENX-05 | Phase 119 | Complete |
| ENDX-01 | Phase 121 | Complete |
| ENDX-02 | Phase 122 | Complete |
| ENDX-03 | Phase 123 | Complete |
| ENDX-04 | Phase 124 | Complete |
| ENDX-05 | Phase 124 | Complete |
| EXTMAX-01 | Phase 125 | Complete |
| EXTMAX-02 | Phase 126 | Complete |
| EXTMAX-03 | Phase 126 | Complete |
| EXTMAX-04 | Phase 127 | Complete |
| EXTMAX-05 | Phase 128 | Complete |
| RAILMAX-01 | Phase 132 | Complete |
| RAILMAX-02 | Phase 131 | Complete |
| RAILMAX-03 | Phase 132 | Complete |
| RAILMAX-04 | Phase 129 | Complete |
| RAILMAX-05 | Phase 132 | Complete |
| INSMAX-01 | Phase 133 | Complete |
| INSMAX-02 | Phase 134 | Complete |
| INSMAX-03 | Phase 135 | Complete |
| INSMAX-04 | Phase 136 | Complete |
| INSMAX-05 | Phase 136 | Complete |
| TRUSTMAX-01 | Phase 137 | Complete |
| TRUSTMAX-02 | Phase 138 | Complete |
| TRUSTMAX-03 | Phase 139 | Complete |
| TRUSTMAX-04 | Phase 139 | Complete |
| TRUSTMAX-05 | Phase 140 | Complete |
| IDMAX-01 | Phase 141 | Complete |
| IDMAX-02 | Phase 142 | Complete |
| IDMAX-03 | Phase 143 | Complete |
| IDMAX-04 | Phase 143 | Complete |
| IDMAX-05 | Phase 144 | Complete |
| W3STACK-01 | Phase 145 | Complete |
| W3STACK-02 | Phase 146 | Complete |
| W3STACK-03 | Phase 147 | Complete |
| W3STACK-04 | Phase 148 | Complete |
| W3STACK-05 | Phase 148 | Complete |
| LINKX-01 | Phase 149 | Complete |
| LINKX-02 | Phase 150 | Complete |
| LINKX-03 | Phase 149 | Complete |
| LINKX-04 | Phase 151 | Complete |
| LINKX-05 | Phase 152 | Complete |
| ANCHORX-01 | Phase 153 | Complete |
| ANCHORX-02 | Phase 154 | Complete |
| ANCHORX-03 | Phase 155 | Complete |
| ANCHORX-04 | Phase 156 | Complete |
| ANCHORX-05 | Phase 156 | Complete |
| SETTLEX-01 | Phase 157 | Complete |
| SETTLEX-02 | Phase 158 | Complete |
| SETTLEX-03 | Phase 159 | Complete |
| SETTLEX-04 | Phase 160 | Complete |
| SETTLEX-05 | Phase 160 | Complete |
| WEBAUTO-01 | Phase 161 | Complete |
| WEBAUTO-02 | Phase 162 | Complete |
| WEBAUTO-03 | Phase 163 | Complete |
| WEBAUTO-04 | Phase 164 | Complete |
| WEBAUTO-05 | Phase 164 | Complete |
| W3OPS-01 | Phase 165 | Complete |
| W3OPS-02 | Phase 166 | Complete |
| W3OPS-03 | Phase 166 | Complete |
| W3OPS-04 | Phase 167 | Complete |
| W3OPS-05 | Phase 168 | Complete |
| W3INT-01 | Phase 169 | Complete |
| W3INT-02 | Phase 170 | Complete |
| W3INT-03 | Phase 171 | Complete |
| W3INT-04 | Phase 172 | Complete |
| W3INT-05 | Phase 172 | Complete |
| W3REL-01 | Phase 173 | Complete |
| W3REL-02 | Phase 174 | Complete |
| W3REL-03 | Phase 175 | Complete |
| W3REL-04 | Phase 175 | Complete |
| W3REL-05 | Phase 176 | Complete |
| W3SUST-01 | Phase 177 | Complete |
| W3SUST-02 | Phase 178 | Complete |
| W3SUST-03 | Phase 179 | Complete |
| W3SUST-04 | Phase 179 | Complete |
| W3SUST-05 | Phase 180 | Complete |
| MERC-01 | Phase 181 | Complete |
| MERC-02 | Phase 182 | Complete |
| MERC-03 | Phase 182 | Complete |
| MERC-04 | Phase 183 | Complete |
| MERC-05 | Phase 184 | Complete |
| MERC-06 | Phase 181 | Complete |
| SLIVE-01 | Phase 185 | Complete |
| SLIVE-02 | Phase 186 | Complete |
| SLIVE-03 | Phase 187 | Complete |
| SLIVE-04 | Phase 187 | Complete |
| SLIVE-05 | Phase 188 | Complete |
| DOWN-01 | Phase 189 | Complete |
| DOWN-02 | Phase 190 | Complete |
| DOWN-03 | Phase 191 | Complete |
| DOWN-04 | Phase 191 | Complete |
| DOWN-05 | Phase 192 | Complete |
| ASR-01 | Phase 197 | Complete |
| ASR-02 | Phase 198 | Complete |
| ASR-03 | Phase 199 | Complete |
| ASR-04 | Phase 199 | Complete |
| ASR-05 | Phase 200 | Complete |
| OEM-01 | Phase 201 | Complete |
| OEM-02 | Phase 202 | Complete |
| OEM-03 | Phase 203 | Complete |
| OEM-04 | Phase 203 | Complete |
| OEM-05 | Phase 204 | Complete |
| GWB-01 | Phase 193 | Complete |
| GWB-02 | Phase 194 | Complete |
| GWB-03 | Phase 195 | Complete |
| GWB-04 | Phase 195 | Complete |
| GWB-05 | Phase 196 | Complete |
| TRUSTNET-01 | Phase 205 | Complete |
| TRUSTNET-02 | Phase 206 | Complete |
| TRUSTNET-03 | Phase 207 | Complete |
| TRUSTNET-04 | Phase 207 | Complete |
| TRUSTNET-05 | Phase 208 | Complete |
| AWALL-01 | Phase 209 | Complete |
| AWALL-02 | Phase 210 | Complete |
| AWALL-03 | Phase 211 | Complete |
| AWALL-04 | Phase 211 | Complete |
| AWALL-05 | Phase 212 | Complete |
| MHE-01 | Phase 217 | Queued |
| MHE-02 | Phase 218 | Queued |
| MHE-03 | Phase 219 | Queued |
| MHE-04 | Phase 220 | Queued |
| MHE-05 | Phase 220 | Queued |
| MPH-01 | Phase 213 | Complete |
| MPH-02 | Phase 214 | Complete |
| MPH-03 | Phase 214 | Complete |
| MPH-04 | Phase 215 | Complete |
| MPH-05 | Phase 216 | Complete |

**Coverage:**
- Completed requirements tracked here: 225
- Active requirements: 21
- Mapped to phases: 246
- Unmapped: 0

## v3.12 Cross-Protocol Integrity and Truth Completion

Closes the remaining credibility gap between ARC's shipped kernel/substrate
breakthrough and the broader cross-protocol governance claim. This milestone
finishes ACP live-path cryptographic enforcement, makes outward A2A/ACP edges
truthfully kernel-mediated, closes the last operational parity gaps, and
forces the repo/docs/planning story to match the live code.

### ACP Live-Path Cryptographic Enforcement

- [x] **ACPX-01**: `arc-acp-proxy` filesystem and terminal interception paths invoke the configured `CapabilityChecker` before built-in allow logic and fail closed on deny or validation error
- [x] **ACPX-02**: `KernelCapabilityChecker` verifies capability token signatures, time validity, server binding, and scope coverage using configured kernel trust material instead of parse/time/scope checks alone
- [x] **ACPX-03**: ACP live-path receipts or equivalent compliance artifacts record the validated `capability_id` and clearly distinguish cryptographically enforced operations from audit-only permission mapping

### Outward Edge Kernel Mediation

- [x] **EDGE-01**: `arc-a2a-edge` live send/invoke paths route authority decisions through the ARC kernel instead of directly invoking adapter connections
- [x] **EDGE-02**: `arc-a2a-edge` allowed, denied, failed, and streaming flows expose signed receipt output or truthful receipt references rather than implying kernel mediation without evidence
- [x] **EDGE-03**: `arc-acp-edge` capability invocation and permission surfaces are kernel-mediated with signed receipts, or any remaining non-kernel discovery-only paths are explicitly documented and excluded from enforcement claims

### Operational Parity

- [x] **OPER-01**: `arc-api-protect` persists signed receipts when `receipt_db` is configured and exposes the same persisted receipts across proxy and `/arc/evaluate` flows
- [x] **OPER-02**: `arc-tower` binds raw request bodies into evaluation inputs so `body_hash` and `body_length` are populated instead of always `None` / `0`
- [x] **OPER-03**: The Kubernetes controller validates ARC capability tokens and required scopes against kernel-backed logic rather than annotation presence alone

### Truth and Narrative Reconciliation

- [x] **TRUTH-01**: `docs/protocols/STRATEGIC-VISION.md` distinguishes the shipped kernel/substrate breakthrough from future generic cross-protocol orchestration and aligns shipped-status tables with code reality
- [x] **TRUTH-02**: `docs/protocols/HTTP-FRAMEWORK-INTEGRATION-STRATEGY.md` and `docs/sdk/PLATFORM.md` reflect the actual shipped crates/packages, remaining gaps, and precise capability/receipt semantics
- [x] **TRUTH-03**: Planning docs (`PROJECT.md`, `MILESTONES.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md`) consistently represent `v3.12` as the corrective credibility lane and `v4.0` as a parallel strategic bet rather than the active truth narrative
- [x] **TRUTH-04**: Crate-level doc comments and bridge docs no longer state kernel mediation or signed receipt behavior where the live path does not implement it

### Qualification

- [x] **QUAL-01**: Integration tests cover ACP live-path cryptographic enforcement and A2A/ACP outward-edge kernel mediation, including allow, deny, invalid-token, and receipt-emission cases
- [x] **QUAL-02**: Milestone closeout artifacts state the narrow truthful breakthrough claim ARC can defend today and the explicit conditions for any broader "fully realized universal kernel" claim
- [x] **QUAL-03**: Operator-facing verification proves receipt persistence, `arc-tower` body binding, and Kubernetes token/scope enforcement on real runtime paths

## v3.12 Out of Scope

| Feature | Reason |
|---------|--------|
| Generic `CrossProtocolOrchestrator` / `CapabilityBridge` architecture | Remains future work; this milestone closes truth and enforcement gaps on existing in-tree surfaces |
| Net-new protocol adapters beyond current HTTP/MCP/A2A/ACP/OpenAI lanes | Finish credibility on shipped surfaces before expanding protocol breadth again |
| New economic / marketplace claims around "comptroller of the agent economy" | Marketing posture must follow cryptographically proven runtime behavior, not precede it |
| WASM guard runtime completion | Covered by parallel `v4.0` lane |

## v3.12 Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| ACPX-01 | Phase 377 | Complete |
| ACPX-02 | Phase 377 | Complete |
| ACPX-03 | Phase 377 | Complete |
| EDGE-01 | Phase 378 | Complete |
| EDGE-02 | Phase 378 | Complete |
| EDGE-03 | Phase 378 | Complete |
| OPER-01 | Phase 379 | Complete |
| OPER-02 | Phase 379 | Complete |
| OPER-03 | Phase 379 | Complete |
| TRUTH-01 | Phase 380 | Complete |
| TRUTH-02 | Phase 380 | Complete |
| TRUTH-03 | Phase 380 | Complete |
| TRUTH-04 | Phase 380 | Complete |
| QUAL-01 | Phase 381 | Complete |
| QUAL-02 | Phase 381 | Complete |
| QUAL-03 | Phase 381 | Complete |

**Coverage:**
- v3.12 requirements: 16 total
- Mapped to phases: 16
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-14*
*Last updated: 2026-04-14 after completing milestone v3.12 Cross-Protocol Integrity and Truth Completion locally*

## v3.13 Universal Orchestration Closure

Closes the remaining gap between ARC's shipped kernel/substrate breakthrough
and the full original vision. This milestone implements the generic
cross-protocol orchestrator, unifies authoritative edge paths, upgrades bridge
fidelity semantics to truthful publication-gating behavior, and reconciles the
late-v3 ledger and older vision material with the claim gate ARC can actually
defend.

### Cross-Protocol Orchestration

- [x] **ORCH-01**: A reusable `CrossProtocolOrchestrator` exists as the default runtime for bridged protocol execution instead of edge-specific bespoke authority flows
- [x] **ORCH-02**: `CapabilityBridge` plus a cross-protocol capability reference/envelope contract are implemented with provenance, attenuation, and protocol-context fields
- [x] **ORCH-03**: Orchestrated bridge executions emit signed receipts or truthful receipt references that preserve origin protocol and bridge lineage across hops

### Authoritative Edge Unification

- [x] **AUTH-01**: ACP authoritative enforcement routes through a kernel-backed service or guard pipeline rather than local token verification logic alone
- [x] **AUTH-02**: A2A and ACP passthrough helpers are quarantined to explicit compatibility/test surfaces and cannot be confused with default authoritative execution
- [x] **AUTH-03**: Permission-preview APIs remain explicitly non-authoritative and cannot satisfy receipt-bearing execution claims

### Fidelity and Publication Gating

- [x] **FID-01**: Bridge fidelity implements `Lossless`, `Adapted { caveats }`, and `Unsupported { reason }` semantics instead of heuristic `Full/Partial/Degraded` labels
- [x] **FID-02**: Unsupported bridges are not auto-published, and adapted bridges surface caveats in outward metadata and docs
- [x] **FID-03**: Streaming, cancellation, permission-prompt, and partial-output semantics are tested and mapped through fidelity rules rather than side-effect heuristics alone

### Ledger and Narrative Reconciliation

- Late-v3 note: phase-local checkbox sections here remain historical artifacts.
  The authoritative read is that `v3.9-v3.11` are implemented locally with
  audit debt rather than runtime debt, and `v3.13` landed its
  runtime/substrate work before the final ledger/archive closure completed in
  archived `v3.14`.
- [x] **LEDGER-01**: v3.9-v3.11 requirements, roadmap phase tables, and milestone statuses reconcile to actual implementation and verification truth
- [x] **LEDGER-02**: Planning headers and state metadata consistently identify the latest completed milestone, active milestone, true phase status, true plan counts, and the current execution lane
- [x] **LEDGER-03**: v3.0-v3.8 milestone and phase summaries no longer flatten obviously implemented surfaces into unqualified `Planned` placeholders; they either reflect implementation/audit-pending truth or are explicitly deferred for audit
- [x] **TRUTH-05**: Older vision and release material no longer overstates formal verification, economic end-state, or shipped protocol maturity relative to the current claim gate
- [x] **TRUTH-06**: Protocol/design docs no longer describe the shipped cross-protocol substrate or current A2A/ACP edge baseline as unimplemented

### HTTP Authority and Evidence Convergence

- [x] **HTTP-01**: `HttpReceipt.response_status` and corresponding SDK/runtime receipt fields reflect actual downstream response evidence, or are explicitly renamed/documented as evaluation-time semantics instead of proxied response evidence
- [x] **HTTP-02**: `arc-api-protect` honors OpenAPI extension-aware policy overrides (`x-arc-side-effects`, `x-arc-approval-required`, and related runtime policy inputs) during evaluation instead of method defaults alone
- [x] **HTTP-03**: `arc-api-protect` forwards the headers required for real protected reverse-proxy operation rather than a minimal demo subset, with any intentional exclusions documented and tested
- [x] **HTTP-04**: `arc-tower` converges on the shared authority/evidence model instead of a separate embedded evaluator with divergent receipt semantics

### Protocol Lifecycle and Authority-Surface Closure

- [x] **SURFACE-01**: A2A either implements distinct lifecycle semantics for the streamed/task surface it advertises or narrows the advertised/doc surface to the truthful blocking semantics it actually supports
- [x] **SURFACE-02**: ACP either implements the richer session/update/cancel lifecycle it advertises in design material or narrows the advertised/doc surface to the truthful blocking semantics it actually supports
- [x] **SURFACE-03**: Public non-authoritative compatibility APIs are isolated strongly enough that default/public authority surfaces cannot reasonably be mistaken for receipt-bearing mediation
- [x] **SURFACE-04**: Outward discovery handles duplicate tool/capability names and similar publication collisions deterministically and truthfully rather than by silent dropping

### Claim Upgrade Qualification

- [x] **UPGRADE-01**: End-to-end tests cover orchestrated MCP/A2A/ACP/HTTP lineage with signed receipt continuity across bridge hops
- [x] **UPGRADE-02**: Operator-facing claim-gate docs state the strongest honest post-v3 claim ARC can make, explicitly distinguishing the shipped edge-to-native substrate from future full protocol-to-protocol orchestration and broader economic thesis
- [x] **UPGRADE-03**: Qualification evidence proves the orchestrator and unified edges preserve fail-closed behavior, authority-path clarity, and receipt continuity under real runtime flows

## v3.13 Out of Scope

| Feature | Reason |
|---------|--------|
| New economic / liability marketplace claims | Follows only after orchestrated governance is real and operator evidence exists |
| Full dynamic or intent-aware governance | Separate future layer after deterministic orchestration closure |
| Net-new protocol adapters beyond MCP/A2A/ACP/OpenAI/HTTP | Close authority split and fidelity truth on existing surfaces first |
| v4.x WASM guard SDK / WIT work | Parallel strategic lane, not part of this closure milestone |

## v3.13 Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| ORCH-01 | Phase 390 | Complete |
| ORCH-02 | Phase 390 | Complete |
| ORCH-03 | Phase 390 | Complete |
| AUTH-01 | Phase 391 | Complete |
| AUTH-02 | Phase 391 | Complete |
| AUTH-03 | Phase 391 | Complete |
| FID-01 | Phase 392 | Complete |
| FID-02 | Phase 392 | Complete |
| FID-03 | Phase 392 | Complete |
| LEDGER-01 | Phase 393 / 401 | Complete |
| LEDGER-02 | Phase 393 | Complete |
| LEDGER-03 | Phase 393 / 401 | Complete |
| TRUTH-05 | Phase 393 / 396 | Complete |
| TRUTH-06 | Phase 393 / 396 | Complete |
| HTTP-01 | Phase 394 | Complete |
| HTTP-02 | Phase 394 | Complete |
| HTTP-03 | Phase 394 | Complete |
| HTTP-04 | Phase 394 | Complete |
| SURFACE-01 | Phase 395 | Complete |
| SURFACE-02 | Phase 395 | Complete |
| SURFACE-03 | Phase 395 | Complete |
| SURFACE-04 | Phase 395 | Complete |
| UPGRADE-01 | Phase 396 | Complete |
| UPGRADE-02 | Phase 396 | Complete |
| UPGRADE-03 | Phase 396 | Complete |

**Coverage:**
- v3.13 requirements: 25 total
- Mapped to phases: 25
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-14*
*Last updated: 2026-04-14 after completing phases 394-396 and qualifying the cross-protocol runtime gate*

## v3.14 Universal Fabric and Kernel Convergence

Closes the remaining gap between ARC's qualified cross-protocol execution
substrate and the stronger original vision. This milestone extends the
orchestrator from edge-to-native execution into a protocol-to-protocol fabric,
converges supported HTTP/API surfaces on one literal kernel authority story,
finishes the remaining lifecycle and compatibility-surface truth work, and
repairs the historical milestone/archive ledger so the final claim gate can be
decided from one honest source of record.

### Protocol-to-Protocol Fabric

- [x] **FABRIC-01**: `CrossProtocolOrchestrator` resolves target protocols through an explicit bridge registry and bridge metadata instead of collapsing every authoritative execution to `Native`
- [x] **FABRIC-02**: At least one authoritative bridge path executes protocol-to-protocol without terminating immediately in `DiscoveryProtocol::Native`
- [x] **FABRIC-03**: Multi-hop bridge execution preserves attenuation, trace lineage, fidelity semantics, and receipt/evidence references across each hop

### Kernel-First HTTP and SDK Convergence

- [x] **KERNEL-01**: `arc-api-protect` routes authorization and receipt finalization through one shared kernel-backed authority path instead of a local evaluator/signer
- [x] **KERNEL-02**: `arc-tower` uses the same shared kernel-backed authority/evidence path as `arc-api-protect` rather than a parallel evaluator implementation
- [x] **KERNEL-03**: Representative HTTP/API SDK substrates (TypeScript, Python, Go, JVM, and .NET) converge on the shared authority/evidence contract and do not synthesize misleading fail-open receipts
- [x] **KERNEL-04**: For the supported HTTP/API surfaces ARC publicly claims, governed invocations can be described literally and truthfully as flowing through one shared kernel authority story

### Lifecycle-Equivalent Protocol Mediation

- [x] **LIFE-01**: A2A authoritative execution distinguishes blocking and streaming/task lifecycles strongly enough to justify the public surface ARC claims
- [x] **LIFE-02**: ACP authoritative execution supports the invoke/stream/cancel/resume lifecycle ARC claims, or the official ACP profile is narrowed with no contradictory public surface
- [x] **LIFE-03**: Non-authoritative A2A/ACP compatibility helpers are internalized, feature-gated, or otherwise isolated so public/default surfaces cannot be mistaken for receipt-bearing authority

### Ledger and Archival Truth

- [x] **LEDGER-01**: `STATE.md`, `PROJECT.md`, `MILESTONES.md`, `REQUIREMENTS.md`, and `ROADMAP.md` agree on the active milestone, latest completed milestone, archival status, and next executable phase
- [x] **LEDGER-02**: v3.0-v3.8 milestone and phase summaries reflect implementation/audit-pending truth rather than blanket `Planned` placeholders
- [x] **LEDGER-03**: v3.9-v3.13 requirement checklists, traceability tables, and milestone status summaries reconcile to the same implementation and verification truth
- [x] **LEDGER-04**: v3.12 and v3.13 archival is complete locally, and any remaining local-only milestone state is called out explicitly rather than implicitly

### Full-Vision Qualification

- [x] **VISION-01**: Qualification evidence covers protocol-to-protocol bridge execution, unified HTTP/API kernel authority, and the supported A2A/ACP lifecycle surfaces without overstating unsupported paths
- [x] **VISION-02**: `docs/protocols/`, `docs/release/`, `docs/standards/`, and `docs/VISION.md` all make the same strongest honest claim about ARC's current state
- [x] **VISION-03**: If ARC can now honestly claim the stronger original vision, the repo ships the evidence and exact claim text needed to do so; otherwise one authoritative claim-gate document names the remaining blockers
- [x] **VISION-04**: Economic/control-plane language is either bounded to strategic research or tied to explicit shipped/runtime qualification evidence rather than aspirational prose

## v3.14 Out of Scope

| Feature | Reason |
|---------|--------|
| Net-new protocol families beyond HTTP, MCP, OpenAI, A2A, and ACP | Close the remaining truth and authority gaps on the existing surfaces first |
| New economic or marketplace runtime features | The goal is to qualify or narrow the existing claim, not expand product surface |
| Broad ecosystem or market-adoption proof | This milestone can tighten the claim gate, but not manufacture external market validation |
| v4.x WASM guard SDK / WIT work | Parallel strategic lane, not part of the post-v3 full-vision closure work |

## v3.14 Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| FABRIC-01 | Phase 397 | Complete |
| FABRIC-02 | Phase 397 | Complete |
| FABRIC-03 | Phase 397 | Complete |
| KERNEL-01 | Phase 398 | Complete |
| KERNEL-02 | Phase 398 | Complete |
| KERNEL-03 | Phase 399 | Complete |
| KERNEL-04 | Phase 399 | Complete |
| LIFE-01 | Phase 400 | Complete |
| LIFE-02 | Phase 400 | Complete |
| LIFE-03 | Phase 400 | Complete |
| LEDGER-01 | Phase 401 | Complete |
| LEDGER-02 | Phase 401 | Complete |
| LEDGER-03 | Phase 401 | Complete |
| LEDGER-04 | Phase 401 | Complete |
| VISION-01 | Phase 402 | Complete |
| VISION-02 | Phase 402 | Complete |
| VISION-03 | Phase 402 | Complete |
| VISION-04 | Phase 402 | Complete |

**Coverage:**
- v3.14 requirements: 18 total
- Mapped to phases: 18
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-14*
*Last updated: 2026-04-14 after archiving milestone v3.14 Universal Fabric and Kernel Convergence locally*

## v3.15 Universal Protocol Fabric Realization

Closes the remaining post-v3.14 gap between ARC's qualified cross-protocol
substrate and the full original vision. This milestone lifts target-protocol
selection into shared bridge metadata and registry-driven bindings, removes
the remaining authoritative-edge `Native` defaults, pushes the public
lifecycle surfaces toward real symmetry where ARC wants to claim it, and
finishes the final v3 planning/archive truth closure before another full
qualification pass.

### Protocol-Aware Fabric Routing

- [ ] **FABRIC2-01**: shared bridge metadata expresses target protocol explicitly for outward-authoritative tool bindings instead of forcing A2A/ACP to hardcode `DiscoveryProtocol::Native`
- [ ] **FABRIC2-02**: both A2A and ACP authoritative execution can select a non-native target protocol from shared binding metadata without bespoke edge-only helper methods
- [ ] **FABRIC2-03**: the bridge architecture docs distinguish the shipped protocol-aware substrate from the still-future universal multi-hop registry/fabric end-state without stale contradictions

### Lifecycle-Equivalent Mediation

- [x] **LIFE2-01**: A2A authoritative mediation either ships a receipt-bearing `message/stream` / task-progress lifecycle that matches the public symmetry claim, or the official claim gate excludes lifecycle equivalence until it does
- [x] **LIFE2-02**: ACP authoritative mediation either ships truthful `tool/stream`, `tool/cancel`, and `tool/resume` behavior for the public profile ARC wants to claim, or the official claim gate excludes lifecycle equivalence until it does
- [x] **LIFE2-03**: any remaining compatibility-only bypasses are internalized or clearly isolated enough that the public/default surface cannot be mistaken for the receipt-bearing authority path

### Ledger and Archival Truth Closure

- [x] **LEDGER2-01**: `STATE.md`, `PROJECT.md`, `MILESTONES.md`, `ROADMAP.md`, and `REQUIREMENTS.md` all identify `v3.15` as the active lane, `v3.14` as the most recent implemented lane, and the archived milestone boundary truthfully
- [x] **LEDGER2-02**: `v3.14` is archived locally once the follow-on lane is stable, and any remaining non-archived v3 milestones are called out explicitly
- [x] **LEDGER2-03**: early-v3 top-level milestone labels, detailed phase tables, and per-milestone requirement sections now tell one coherent implementation/audit-pending story

### Full-Vision Requalification

- [ ] **QUAL2-01**: `STRATEGIC-VISION.md`, `QUALIFICATION.md`, `RELEASE_AUDIT.md`, and `ARC_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json` are rerun against the post-v3.15 runtime instead of older bounded-fabric assumptions
- [ ] **QUAL2-02**: ARC upgrades to the stronger original-vision claim only if protocol-aware fabric routing, lifecycle-equivalent mediation, and ledger/archive truth are all demonstrably complete
- [ ] **QUAL2-03**: if the stronger claim still does not qualify, one authoritative blocker list explains exactly what remains without conflicting docs or milestone state

## v3.15 Out of Scope

| Feature | Reason |
|---------|--------|
| New protocol families beyond the existing MCP/A2A/ACP/OpenAI/HTTP set | Finish truthful symmetry and qualification on shipped families first |
| Economic or agent-market dominance claims beyond the execution/control substrate | These follow only after the stronger orchestration/runtime claim is honestly qualified |
| WASM guard SDK / WIT work | Continues in parallel `v4.x` lane |

## v3.15 Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| FABRIC2-01 | Phase 403 | Complete |
| FABRIC2-02 | Phase 403 | Complete |
| FABRIC2-03 | Phase 403 | Complete |
| LIFE2-01 | Phase 404 | Complete |
| LIFE2-02 | Phase 404 | Complete |
| LIFE2-03 | Phase 404 | Complete |
| LEDGER2-01 | Phase 405 | Complete |
| LEDGER2-02 | Phase 405 | Complete |
| LEDGER2-03 | Phase 405 | Complete |
| QUAL2-01 | Phase 406 | Planned |
| QUAL2-02 | Phase 406 | Planned |
| QUAL2-03 | Phase 406 | Planned |

**Coverage:**
- v3.15 requirements: 12 total
- Mapped to phases: 12
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-14*
*Last updated: 2026-04-14 after completing phase 405 final v3 ledger and archive closure locally*

## v4.0 WASM Guard Runtime Completion

Completes the arc-wasm-guards host-side runtime that Phase 347 scaffolded.
Extends v3.7's WASM guard skeleton into a production-ready, HushSpec-aware
guard execution surface. Design docs: `docs/guards/01-05`.

### Runtime Hardening

- [x] **WGRT-01**: WasmtimeBackend shares a single `Arc<Engine>` across all loaded WASM guards instead of creating one Engine per guard
- [x] **WGRT-02**: WasmtimeBackend uses a `WasmHostState` struct in the Store instead of `()`, carrying guard config and a log buffer
- [x] **WGRT-03**: WASM guards can call `arc.log(level, msg_ptr, msg_len)` host function to emit structured tracing log lines
- [x] **WGRT-04**: WASM guards can call `arc.get_config(key_ptr, key_len, val_out_ptr, val_out_len)` host function to read manifest config values
- [x] **WGRT-05**: WASM guards can call `arc.get_time_unix_secs()` host function to read wall-clock time
- [x] **WGRT-06**: Host checks for guest-exported `arc_alloc` and uses it for request memory allocation, falling back to offset-0 write when absent
- [x] **WGRT-07**: Host checks for guest-exported `arc_deny_reason` and uses it to read structured deny reasons, falling back to offset-64K NUL-terminated string when absent

### Security

- [x] **WGSEC-01**: ResourceLimiter caps guest linear memory growth (configurable, default 16 MiB)
- [x] **WGSEC-02**: Module import validation rejects WASM modules that import functions outside the `arc` namespace (no WASI, no unknown imports)
- [x] **WGSEC-03**: Module size is validated at load time against a configurable maximum

### Guard Request Enrichment

- [x] **WGREQ-01**: GuardRequest includes `action_type` field pre-extracted by the host via `extract_action()`
- [x] **WGREQ-02**: GuardRequest includes `extracted_path` field with normalized file path for filesystem actions
- [x] **WGREQ-03**: GuardRequest includes `extracted_target` field with domain string for network egress actions
- [x] **WGREQ-04**: GuardRequest includes `filesystem_roots` field from session context
- [x] **WGREQ-05**: GuardRequest includes `matched_grant_index` field from capability scope
- [x] **WGREQ-06**: `session_metadata` field is removed from GuardRequest (always None, replaced by structured fields)

### Guard Manifest

- [x] **WGMAN-01**: Guard manifest format (`guard-manifest.yaml`) defines name, version, abi_version, wasm path, config schema, and wasm_sha256
- [x] **WGMAN-02**: Host verifies wasm_sha256 against actual .wasm binary content at load time and rejects mismatches
- [x] **WGMAN-03**: Host validates abi_version from manifest and rejects unsupported versions
- [x] **WGMAN-04**: Guard config values are loaded from manifest config block and made available via `arc.get_config` host function

### Startup Wiring

- [x] **WGWIRE-01**: Startup code loads HushSpec-compiled guards via `arc_policy::compiler::compile_policy()` and registers them first in the kernel pipeline
- [x] **WGWIRE-02**: Startup code sorts `WasmGuardEntry` list by priority field before loading into WasmGuardRuntime
- [x] **WGWIRE-03**: Startup code registers WASM guards after HushSpec guards and before the advisory pipeline
- [x] **WGWIRE-04**: Startup code loads `guard-manifest.yaml` adjacent to each .wasm path and passes config to WasmHostState

### Receipt Integration

- [x] **WGRCPT-01**: When a WASM guard evaluates, fuel consumed is recorded and available for inclusion in receipt metadata
- [x] **WGRCPT-02**: When a WASM guard evaluates, the guard manifest SHA-256 hash is recorded and available for inclusion in receipt metadata

### Benchmarks

- [x] **WGBENCH-01**: Benchmark measures wasmtime Module::new() compilation time for representative .wasm guard binaries (50 KiB Rust, 5 MiB Python-via-componentize-py)
- [x] **WGBENCH-02**: Benchmark measures Linker::instantiate() per-call overhead
- [x] **WGBENCH-03**: Benchmark measures p50/p99 evaluate latency for a trivial guard (immediate Allow) and a realistic guard (JSON parse + pattern match + Deny)
- [x] **WGBENCH-04**: Benchmark measures fuel metering overhead percentage (fuel enabled vs disabled)
- [x] **WGBENCH-05**: Benchmark verifies ResourceLimiter actually caps memory growth under adversarial guest allocation

## v4.0 Out of Scope

| Feature | Reason |
|---------|--------|
| WIT / Component Model ABI | v4.2 -- validate raw ABI on real workloads first |
| Guest-side Rust SDK / proc macro | v4.1 -- host must be stable before guest SDK |
| Non-Rust guest SDKs (TS, Python, Go) | v4.2 -- after WIT migration |
| CLI tooling (arc guard new/build/test/pack) | v4.1 -- developer experience milestone |
| Guard registry / marketplace / OCI | v4.2+ -- ecosystem maturity |
| Persistent per-guard state across calls | Requires state model redesign |
| Async host functions / network access | Kernel Guard trait is sync |
| WasmGuardEntry.config field in arc.yaml | v4.0.1 fast-follow after manifest validation |
| Epoch interruption | v4.0.1 -- secondary timeout after fuel validation |
| Severity on GuardVerdict::Deny | v4.0.1 -- receipts-only, not advisory promotion |

## v4.0 Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| WGRT-01 | Phase 373 | Complete |
| WGRT-02 | Phase 373 | Complete |
| WGRT-03 | Phase 373 | Complete |
| WGRT-04 | Phase 373 | Complete |
| WGRT-05 | Phase 373 | Complete |
| WGRT-06 | Phase 373 | Complete |
| WGRT-07 | Phase 373 | Complete |
| WGSEC-01 | Phase 374 | Complete |
| WGSEC-02 | Phase 374 | Complete |
| WGSEC-03 | Phase 374 | Complete |
| WGREQ-01 | Phase 374 | Complete |
| WGREQ-02 | Phase 374 | Complete |
| WGREQ-03 | Phase 374 | Complete |
| WGREQ-04 | Phase 374 | Complete |
| WGREQ-05 | Phase 374 | Complete |
| WGREQ-06 | Phase 374 | Complete |
| WGMAN-01 | Phase 375 | Complete |
| WGMAN-02 | Phase 375 | Complete |
| WGMAN-03 | Phase 375 | Complete |
| WGMAN-04 | Phase 375 | Complete |
| WGWIRE-01 | Phase 375 | Complete |
| WGWIRE-02 | Phase 375 | Complete |
| WGWIRE-03 | Phase 375 | Complete |
| WGWIRE-04 | Phase 375 | Complete |
| WGRCPT-01 | Phase 375 | Complete |
| WGRCPT-02 | Phase 375 | Complete |
| WGBENCH-01 | Phase 376 | Complete |
| WGBENCH-02 | Phase 376 | Complete |
| WGBENCH-03 | Phase 376 | Complete |
| WGBENCH-04 | Phase 376 | Complete |
| WGBENCH-05 | Phase 376 | Complete |

**Coverage:**
- v4.0 requirements: 31 total
- Mapped to phases: 31
- Unmapped: 0 ✓

## v4.1 Guard SDK and Developer Experience

Guest-side Rust SDK with proc macro so guard authors write
`fn evaluate(req) -> verdict` and compile to wasm32-unknown-unknown.
CLI tooling for the full guard development lifecycle. Depends on v4.0
(host runtime must be stable before guest SDK targets it).
Design docs: `docs/guards/03-IMPLEMENTATION-PLAN.md` Phases 2-3.

### Guest SDK

- [x] **GSDK-01**: `arc-guard-sdk` crate provides `GuardRequest` and `GuardVerdict` types matching the host ABI
- [x] **GSDK-02**: `arc-guard-sdk` crate implements a guest-side allocator exported as `arc_alloc` and `arc_free`
- [x] **GSDK-03**: `arc-guard-sdk` crate provides typed host function bindings for `arc::log`, `arc::get_config`, and `arc::get_time`
- [x] **GSDK-04**: `arc-guard-sdk` crate handles `GuardRequest` deserialization from linear memory and `GuardVerdict` encoding back to the host
- [x] **GSDK-05**: `arc-guard-sdk` crate exports `arc_deny_reason` for structured deny reason reporting
- [x] **GSDK-06**: `arc-guard-sdk-macros` crate provides `#[arc_guard]` proc macro that generates the `evaluate` export, allocator, and ABI glue from a user function

### Example Guards

- [x] **GEXM-01**: An example guard using the SDK demonstrates allowing or denying based on tool name inspection
- [x] **GEXM-02**: An example guard using the SDK demonstrates reading `action_type` and `extracted_path` from the enriched GuardRequest
- [x] **GEXM-03**: An example guard using the SDK demonstrates calling `arc::log` and `arc::get_config` host functions
- [x] **GEXM-04**: Example guards compile to `wasm32-unknown-unknown` and produce valid .wasm binaries
- [x] **GEXM-05**: Integration test loads an example guard .wasm into WasmtimeBackend, evaluates it against test requests, and verifies correct Allow/Deny verdicts

### CLI Scaffolding

- [x] **GCLI-01**: `arc guard new <name>` scaffolds a new guard project with Cargo.toml, src/lib.rs using `#[arc_guard]`, and guard-manifest.yaml
- [x] **GCLI-02**: `arc guard build` compiles the guard to `wasm32-unknown-unknown` release and reports binary size
- [x] **GCLI-03**: `arc guard inspect <path>` reads a .wasm file and prints exported functions, ABI compatibility, and memory requirements

### CLI Test and Package

- [x] **GCLI-04**: `arc guard test` loads a compiled .wasm and runs it against YAML test fixture files with expected verdicts
- [x] **GCLI-05**: Test fixture YAML format specifies request fields, expected verdict (allow/deny), and optional expected deny reason substring
- [x] **GCLI-06**: `arc guard bench <path>` measures fuel consumption and execution time on sample requests and reports p50/p99
- [x] **GCLI-07**: `arc guard pack` creates a distributable `.arcguard` archive (gzipped tar) from guard-manifest.yaml + .wasm binary
- [x] **GCLI-08**: `arc guard install <path>` extracts an `.arcguard` archive to the configured guard directory

## v4.1 Out of Scope

| Feature | Reason |
|---------|--------|
| Non-Rust guest SDKs (TS, Python, Go) | v4.2 -- after WIT migration |
| WIT interface definition | v4.2 -- raw ABI must be stable first |
| Guard registry / marketplace | v4.2+ -- ecosystem maturity |
| OCI distribution | v4.2+ -- after packaging is validated |
| `arc guard publish` (remote upload) | v4.2+ -- needs registry |
| Guard signing (beyond SHA-256) | v4.2+ -- needs key management story |

## v4.1 Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| GSDK-01 | Phase 377 | Complete |
| GSDK-02 | Phase 377 | Complete |
| GSDK-03 | Phase 377 | Complete |
| GSDK-04 | Phase 377 | Complete |
| GSDK-05 | Phase 377 | Complete |
| GSDK-06 | Phase 378 | Complete |
| GEXM-01 | Phase 378 | Complete |
| GEXM-02 | Phase 378 | Complete |
| GEXM-03 | Phase 378 | Complete |
| GEXM-04 | Phase 378 | Complete |
| GEXM-05 | Phase 378 | Complete |
| GCLI-01 | Phase 379 | Complete |
| GCLI-02 | Phase 379 | Complete |
| GCLI-03 | Phase 379 | Complete |
| GCLI-04 | Phase 380 | Complete |
| GCLI-05 | Phase 380 | Complete |
| GCLI-06 | Phase 380 | Complete |
| GCLI-07 | Phase 380 | Complete |
| GCLI-08 | Phase 380 | Complete |

**Coverage:**
- v4.1 requirements: 19 total
- Mapped to phases: 19
- Unmapped: 0 ✓

## v4.2 WIT Migration and Multi-Language SDKs

Migrates the WASM guard ABI from raw core-WASM to the Component Model with
a WIT-defined interface. Ships TypeScript, Python, and Go guest SDKs so
guard authors can write policy in any major language. Cross-language
conformance test suite validates all SDKs against the same fixtures.
Depends on v4.1 (Rust SDK and raw ABI must be stable).
Design docs: `docs/guards/02-WASM-RUNTIME-LANDSCAPE.md` Sections 3-4,
`docs/guards/03-IMPLEMENTATION-PLAN.md` Phase 4.

### WIT Interface

- [x] **WIT-01**: Guard WIT interface defined (`arc:guard@0.1.0`) with `evaluate` function, `guard-request` record, and `verdict` variant types
- [x] **WIT-02**: Host implements the WIT interface using `wasmtime::component::bindgen!` with generated Rust types
- [x] **WIT-03**: Host supports dual-mode loading: raw core-WASM modules (legacy ABI) and Component Model components (WIT ABI) detected at load time
- [x] **WIT-04**: WIT package published in-repo under `wit/arc-guard/` with versioned world definition

### TypeScript SDK

- [x] **TSDK-01**: TypeScript guard SDK (`packages/sdk/arc-guard-ts`) provides typed `GuardRequest` and `GuardVerdict` interfaces matching the WIT contract
- [x] **TSDK-02**: TypeScript guards compile to WASM components via `jco` / ComponentizeJS
- [x] **TSDK-03**: TypeScript SDK includes example guard with build instructions
- [x] **TSDK-04**: TypeScript-compiled guard loads and evaluates correctly in the host dual-mode runtime

### Python SDK

- [x] **PYDK-01**: Python guard SDK (`packages/sdk/arc-guard-py`) provides typed dataclasses matching the WIT contract
- [x] **PYDK-02**: Python guards compile to WASM components via `componentize-py`
- [x] **PYDK-03**: Python SDK includes example guard with build instructions
- [x] **PYDK-04**: Python-compiled guard loads and evaluates correctly in the host dual-mode runtime

### Go SDK

- [x] **GODK-01**: Go guard SDK (`packages/sdk/arc-guard-go`) provides typed structs matching the WIT contract
- [x] **GODK-02**: Go guards compile to WASM components via TinyGo with `wasip2` target
- [x] **GODK-03**: Go SDK includes example guard with build instructions
- [x] **GODK-04**: Go-compiled guard loads and evaluates correctly in the host dual-mode runtime

### Conformance

- [ ] **CONF-01**: Cross-language conformance test suite with shared YAML fixtures exercising Allow, Deny, deny-reason, host function calls, and enriched request fields
- [ ] **CONF-02**: Conformance suite runs all four language guards (Rust, TypeScript, Python, Go) against the same fixture set and reports pass/fail per guard per fixture
- [ ] **CONF-03**: Conformance suite validates that fuel consumption is within 2x across languages for the same fixture

## v4.2 Out of Scope

| Feature | Reason |
|---------|--------|
| Guard registry / marketplace | v4.3+ -- needs community adoption first |
| OCI distribution | v4.3+ -- after packaging model validated |
| Guard signing with key management | v4.3+ -- needs identity story |
| Async host functions | Requires kernel Guard trait redesign |
| Persistent per-guard state | Requires state model redesign |
| WASI capabilities (filesystem, network) | Guards must remain sandboxed |

## v4.2 Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| WIT-01 | Phase 381 | Complete |
| WIT-02 | Phase 381 | Complete |
| WIT-03 | Phase 381 | Complete |
| WIT-04 | Phase 381 | Complete |
| TSDK-01 | Phase 382 | Complete |
| TSDK-02 | Phase 382 | Complete |
| TSDK-03 | Phase 382 | Complete |
| TSDK-04 | Phase 382 | Complete |
| PYDK-01 | Phase 383 | Complete |
| PYDK-02 | Phase 383 | Complete |
| PYDK-03 | Phase 383 | Complete |
| PYDK-04 | Phase 383 | Complete |
| GODK-01 | Phase 383 | Complete |
| GODK-02 | Phase 383 | Complete |
| GODK-03 | Phase 383 | Complete |
| GODK-04 | Phase 383 | Complete |
| CONF-01 | Phase 384 | Pending |
| CONF-02 | Phase 384 | Pending |
| CONF-03 | Phase 384 | Pending |

**Coverage:**
- v4.2 requirements: 19 total
- Mapped to phases: 19
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-27*
*Last updated: 2026-04-14 after defining milestone v4.2 WIT Migration and Multi-Language SDKs*
