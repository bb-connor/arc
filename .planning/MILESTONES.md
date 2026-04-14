# Milestones

## Active Milestone

### v2.83 Coverage, Hardening, and Production Qualification

**Status:** active locally -- phase `315` is complete and phases `316` through
`318` are the next queued execution target set
**Executable phases:** 315-318
**Goal:** Close the integration-test gap across every workspace crate, push
coverage from 67% to 80%+, introduce connection pooling or an async store
trait for the SQLite layer, audit dead code and over-exported APIs, refactor
the 82 `too_many_arguments` sites, and add structured error output with codes
and suggested fixes.

**Why this milestone matters:** Security-conscious adopters evaluating ARC for
production will audit test coverage, error quality, and API surface. Half the
crates have no integration tests, the store layer uses a single unpooled
connection, and 82 clippy suppressions indicate API design debt. This is the
"prove it works" milestone that earns enterprise trust.

**Key intended outcomes:**
- Integration tests for all workspace crates
- Coverage at 80%+ with focus on security-critical paths
- SQLite connection pooling or async store trait
- Dead code removed, pub visibility audited
- Config/builder structs replace too_many_arguments call sites
- Structured error output with error codes and fix suggestions

## Planned Milestones

### v3.0 Universal Security Kernel Foundation

**Status:** planned
**Executable phases:** 319-322
**Goal:** Build the shared HTTP security types (`arc-http-core`), OpenAPI
import (`arc-openapi`), minimal unified configuration (`arc.yaml`), and the
zero-code reverse-proxy entry point (`arc api protect`).

**Key intended outcomes:**
- `arc-http-core` crate with normalized request, session, receipt, and verdict
  types for HTTP/API surfaces
- `arc-openapi` crate that parses OpenAPI 3.x specs and generates ARC
  ToolManifest entries with default policies
- Minimal `arc.yaml` schema covering kernel, adapters, edges, receipts, and
  logging sections with env-var interpolation and fail-fast validation
- `arc api protect` CLI command that starts a reverse proxy, reads an OpenAPI
  spec, and produces signed receipts for every request
- Deny-by-default for side-effect routes (POST/PUT/DELETE) without a
  capability token

**Why this milestone matters:** Without HTTP/API substrate types and a
zero-code onboarding path, ARC remains a protocol-adapter collection rather
than a universal security kernel. This milestone creates the foundation every
later substrate, SDK, and framework wrapper depends on.

### v3.1 Attestation Completion

**Status:** planned
**Executable phases:** 323-326
**Goal:** Promote ACP proxy events from unsigned audit entries to fully signed
ARC receipts, implement session compliance certificate generation and
verification, and export receipt data as OpenTelemetry spans.

**Key intended outcomes:**
- `ReceiptSigner` trait in `arc-acp-proxy` with kernel-backed implementation
  that signs ACP tool-call events into `ArcReceipt` objects
- `CapabilityChecker` trait for pre-forward capability validation on ACP
  filesystem and terminal operations
- `SessionComplianceCertificate` generation from the kernel's receipt log,
  covering all six assertions (capability validity, scope containment, budget
  compliance, guard passage, no escalation, chain completeness)
- Certificate verification API (lightweight and full-bundle modes)
- `arc cert generate`, `arc cert verify`, and `arc cert inspect` CLI commands
- OpenTelemetry span export for receipt data via `arc-otel` crate or module

**Why this milestone matters:** Unsigned ACP events are the largest
attestation gap in the current stack. Compliance certificates are the
single-artifact auditor handoff that enterprise buyers need. OTel export
connects ARC to existing observability infrastructure.

### v3.2 Python Adoption

**Status:** planned
**Executable phases:** 327-330
**Goal:** Ship a Python SDK, ASGI middleware, FastAPI wrapper, Django
middleware, and LangChain integration so Python developers can adopt ARC with
one import.

**Key intended outcomes:**
- `arc-sdk-python` thin HTTP client package that communicates with the ARC
  sidecar and exposes typed Python classes for capabilities, receipts, and
  guard evaluation
- `arc-asgi` ASGI middleware that intercepts requests, evaluates capabilities,
  runs guards, and signs receipts
- `arc-fastapi` wrapper with decorators for per-route scope, approval, and
  budget constraints
- `arc-django` middleware for WSGI/Django with ORM-aware session handling
- `arc-langchain` integration wrapping ARC-governed tools as LangChain Tool
  objects
- Conformance tests validating Python SDK against the Rust kernel's behavior

**Why this milestone matters:** Python is the dominant language in AI/ML agent
development. Without native Python packaging, ARC adoption requires Rust
expertise or sidecar deployment. This milestone makes ARC reachable for the
largest developer segment building agent systems.

### v3.3 TypeScript Adoption

**Status:** planned
**Executable phases:** 331-334
**Goal:** Ship a Node/Bun HTTP substrate, Express middleware, Fastify plugin,
and Elysia lifecycle hook so TypeScript developers can adopt ARC natively.

**Key intended outcomes:**
- `@arc-protocol/node-http` substrate package handling the common
  `(req, res)` / `Request -> Response` interception model
- `@arc-protocol/express` middleware wrapping node-http for Express apps
- `@arc-protocol/fastify` plugin wrapping node-http for Fastify apps
- `@arc-protocol/elysia` lifecycle hook wrapping node-http for Elysia apps
- npm packages published with TypeScript type definitions
- Conformance tests validating TypeScript SDK against the Rust kernel's
  behavior

**Why this milestone matters:** TypeScript is the second-largest language in
agent and web API development. Express, Fastify, and Elysia cover the
majority of Node/Bun HTTP server deployments. This milestone completes the
two-language adoption path that captures most agent developers.

### v3.4 Guard Expansion

**Status:** planned
**Executable phases:** 335-338
**Goal:** Add session journal for multi-step context, post-invocation response
hooks, and new deterministic and advisory guards that close the runtime
governance gap.

**Key intended outcomes:**
- Session journal (`arc-http-session`) tracking multi-step request history,
  data-flow accounting, and delegation depth per session
- Post-invocation hook pipeline for response inspection, output sanitization,
  and data-flow metering
- Deterministic guards: InternalNetworkGuard (SSRF prevention),
  AgentVelocityGuard (rate limiting per agent/session), DataFlowGuard
  (cumulative bytes-read/written limits)
- Session-aware deterministic guards: BehavioralSequenceGuard (tool ordering
  policy), ResponseSanitizationGuard (PII/PHI redaction in responses)
- Advisory signals (non-blocking): drift detection, unusual data-volume
  changes, cross-tool exfiltration pattern hints
- All deterministic guards fail closed; advisory signals emit signed evidence
  without blocking

**Why this milestone matters:** Deterministic pre-invocation guards are
necessary but insufficient. Post-invocation response inspection and
session-aware context close the gap between "authorized the request" and
"governed the outcome."

### v3.5 Protocol Breadth

**Status:** planned
**Executable phases:** 339-342
**Goal:** Complete MCP adapter coverage, build the OpenAPI-to-MCP bridge, ship
A2A and ACP outward edge crates, and add an OpenAI function-calling adapter.

**Key intended outcomes:**
- MCP adapter coverage raised from 14 tests to 80+, covering streaming, error
  paths, resource templates, nested flows, and OAuth token refresh
- OpenAPI-to-MCP bridge: an ARC-governed HTTP API can appear as an MCP tool
  surface for agents that speak MCP natively
- `arc-a2a-edge` crate exposing ARC tools as A2A Agent Card skills with
  SendMessage and streaming support
- `arc-acp-edge` crate exposing ARC tools as ACP capabilities with session
  prompt, permission gating, and stdio transport
- `arc-openai` adapter intercepting OpenAI-style function calls through the
  ARC kernel

**Why this milestone matters:** Edge symmetry makes ARC a protocol hub rather
than a protocol consumer. The OpenAI adapter captures the remaining major
agent ecosystem. The MCP-to-OpenAPI bridge extends ARC governance to any
documented HTTP API from MCP clients.

### v3.6 Platform Extensions

**Status:** planned
**Executable phases:** 343-346
**Goal:** Ship Go SDK with net/http middleware, Kubernetes admission controller
and sidecar injector, Rust tower::Layer middleware, and JVM and .NET
substrates.

**Key intended outcomes:**
- `arc-go-http` Go module with `http.Handler` middleware wrapping the ARC
  kernel for net/http, Gin, Echo, Fiber, and chi
- Kubernetes admission controller (`arc-k8s-admission`) that rejects pod
  deployments without valid ARC capability tokens
- Kubernetes sidecar injector (`arc-k8s-injector`) that automatically injects
  `arc api protect` as a sidecar container
- `arc-tower` Rust crate implementing `tower::Layer` for Axum, Tonic, and any
  tower-based service
- `arc-jvm` substrate for Spring Boot, Quarkus, and Micronaut via Servlet
  filter or WebFlux handler
- `arc-dotnet` substrate for ASP.NET Core via middleware pipeline

**Why this milestone matters:** Go, Rust, JVM, and .NET together with Python
and TypeScript cover the vast majority of production API surfaces. K8s
controller and injector bring ARC enforcement to infrastructure-level
deployment policy.

### v3.7 Strategic Bets

**Status:** planned
**Executable phases:** 347-350
**Goal:** Ship WASM guard runtime, receipt metering surface, AG-UI proxy, and
skill/workflow authority extensions for advanced economic and orchestration
use cases.

**Key intended outcomes:**
- WASM guard runtime: custom guards authored in any WASM-compilable language,
  sandboxed execution with deterministic fuel metering
- Receipt metering surface: per-receipt cost attribution, usage dashboards,
  billing-ready receipt metadata for managed service scenarios
- `arc-ag-ui-proxy` securing Agent-to-UI event streams with capability
  validation and signed receipts
- SkillGrant, SkillManifest, and WorkflowReceipt types extending the
  capability model to multi-step skill composition and workflow-level receipts
- Advanced economics: monetary budget enforcement via arc-link oracle,
  parametric pricing inputs for insurance/underwriting integrations

**Why this milestone matters:** WASM guards let the community extend ARC's
governance without forking the kernel. Metering and economics create the
receipt-as-billing-ledger model. AG-UI and skill authority extend ARC to
emerging agent-to-user and orchestrated workflow surfaces.

### v3.8 Normative Specification Alignment

**Status:** planned
**Executable phases:** 351-358
**Goal:** Bring the v3.x public specification, schema, and SDK documentation
into line with the shipped universal security kernel so external consumers can
rely on the documented contract.

**Key intended outcomes:**
- Normative specs for the HTTP substrate, OpenAPI integration, guards,
  configuration, compliance certificates, metering, workflow authority, and
  protocol bridges
- JSON Schemas under `spec/schemas/arc-http/v1/` for the sidecar contract
- SDK reference docs for Python, TypeScript, Go, and platform substrates
- Reconciled design docs under `docs/protocols/` that distinguish rationale
  from normative contract

**Why this milestone matters:** ARC cannot claim portable attestation and
cross-language adoption if the public contract drifts from the implementation.
This milestone makes the v3.x kernel consumable by external implementers.

### v3.9 Runtime Correctness and Contract Remediation

**Status:** active locally
**Executable phases:** 359-363
**Goal:** Close the highest-severity v3.x review gaps by restoring
kernel-mediated OpenAI execution, aligning certificate serialization with the
normative spec, fixing HTTP request binding and capability validation,
stabilizing flaky integration tests, and correcting residual SDK/spec drift.

**Key intended outcomes:**
- `arc-openai` executes function calls through the ARC kernel and returns real
  signed receipt artifacts instead of synthetic receipt references
- Compliance certificates serialize in the normative snake_case wire format and
  remain verifiable through `arc cert`
- `arc-api-protect` and `arc-tower` bind query parameters into request hashes,
  carry `capability_id`, and deny invalid or expired capability tokens
- `mcp_serve` integration tests stop exhibiting order-sensitive flake
- Residual contract drift is closed in `spec/CONFIGURATION.md`, Python SDK
  timeout defaults, and workspace-level lint policy

**Why this milestone matters:** These gaps are the difference between an
interesting internal prototype and an externally credible runtime security
kernel. v3.9 restores trust in the documented fail-closed and signed-evidence
claims.

### v3.10 HTTP Sidecar and Cross-SDK Contract Completion

**Status:** active locally
**Executable phases:** 364-367
**Goal:** Finish the residual v3.x HTTP substrate work by exposing the
normative `/arc/*` sidecar interface in Rust, migrating Python onto that
contract, aligning non-Rust capability presentation semantics, and removing
the remaining misleading HTTP-receipt conversion surface.

**Key intended outcomes:**
- `arc-api-protect` exposes `POST /arc/evaluate`, `POST /arc/verify`, and
  `GET /arc/health` with the normative v3 request/response shapes
- Python SDK, ASGI, Django, and FastAPI wrappers use the `/arc/*` sidecar
  endpoints and `EvaluateResponse` rather than the pre-v3 `/v1/evaluate-http`
  contract
- TypeScript, Go, JVM, and .NET HTTP adapters stop embedding raw capability
  tokens in `ArcHttpRequest.headers`, carry token IDs in `capability_id`, and
  document/query both accepted presentation paths
- `HttpReceipt::to_arc_receipt()` no longer fabricates an invalid signed
  `ArcReceipt`; callers must provide a signing keypair for conversion

**Why this milestone matters:** v3.9 fixed the first wave of correctness
issues, but ARC still lacked an in-repo sidecar implementation for the
normative HTTP substrate and still had cross-language SDK drift. v3.10 closes
the last external-consumption blockers in the HTTP/kernel adoption path.

### v3.11 Sidecar Entrypoint and Body-Integrity Completion

**Status:** active locally
**Executable phases:** 368-372
**Goal:** Finish the final shippability and request-integrity gaps by
shipping the documented `arc api protect` operator entrypoint, preserving
request bodies across Node/JVM middleware, aligning byte-accurate body
hashing across SDKs, and correcting the last HTTP substrate schema/doc
drift.

**Key intended outcomes:**
- `arc` exposes the documented `api protect` subcommand and wires it to
  OpenAPI spec loading or discovery, so operators and the K8s injector can
  launch the sidecar exactly as the docs describe
- TypeScript node/Express/Web interceptors and the JVM Spring filter preserve
  request bodies for downstream handlers while still computing ARC body hashes
- Fastify, JVM, and .NET compute `body_hash` from the raw request bytes, not
  decoded strings or reparsed JSON
- `EvaluateResponse.evidence` is always present on the wire, matching the
  normative schema and generated client expectations
- HTTP JSON schemas model nullable optional fields correctly, and platform
  docs describe capability transport consistently

**Why this milestone matters:** v3.10 closed the first sidecar and SDK
contract gaps, but ARC still could not honestly claim that the documented
`arc api protect` entrypoint was shippable or that its middleware preserved
request semantics while binding content cryptographically. v3.11 closes the
remaining body-integrity and operator-surface gaps that would undermine real
deployments.

### v4.0 WASM Guard Runtime Completion

**Status:** planned
**Executable phases:** 373-376
**Goal:** Complete the arc-wasm-guards host-side runtime that Phase 347
scaffolded. Extend v3.7's WASM guard skeleton into a production-ready,
HushSpec-aware guard execution surface with proper host functions, security
hardening, guard manifests, kernel pipeline wiring, receipt metadata, and
validated performance benchmarks.

**Key intended outcomes:**
- Shared `Arc<Engine>` across all WASM guards with `WasmHostState` carrying
  per-guard config and log buffer
- Host functions (`arc.log`, `arc.get_config`, `arc.get_time_unix_secs`) and
  guest memory protocol (`arc_alloc`, `arc_deny_reason`)
- ResourceLimiter memory caps, module import validation, and module size
  limits
- Enriched GuardRequest with host-extracted action context fields replacing
  session_metadata
- Guard manifest format with SHA-256 verification and ABI version validation
- Startup wiring: HushSpec-compiled guards -> sorted WASM guards -> advisory
  pipeline
- Receipt metadata carrying fuel consumed and manifest SHA-256
- Benchmark suite validating module load, instantiation, evaluate latency,
  fuel overhead, and memory caps

**Why this milestone matters:** Phase 347 scaffolded the WASM guard execution
envelope but left the host functions, security surface, manifest format,
pipeline wiring, and performance validation incomplete. Without these, WASM
guards cannot be loaded from a manifest, cannot interact with the host, have
no memory or import safety, and lack the benchmarks needed to validate the
per-call fresh-Store model. v4.0 closes every gap between the skeleton and a
production-ready WASM guard runtime.

## Deferred Milestone

### v2.71 Web3 Live Activation

**Status:** deferred locally on 2026-04-12 pending external Base Sepolia
operator credentials, reviewed live-chain rollout artifacts, and
OpenTimestamps tooling.
**Executable phases:** 291-294
**Goal:** Activate ARC's web3 settlement, Bitcoin OTS anchoring, and Solana
memo publication on live testnets so the multi-chain proof story is exercised
against real external infrastructure.

## Dependency Graph

```
v2.80 (Foundation)
  |--- v2.81 (Deployable) ---> v2.83 (Hardening) ---> v3.0 (Kernel Foundation)
  |--- v2.82 (Spec)           [parallel with v2.81]

v3.0 (Kernel Foundation)
  |--- v3.1 (Attestation)       [parallel]
  |--- v3.2 (Python)            [parallel]
  |--- v3.3 (TypeScript)        [parallel]
  |--- v3.4 (Guards)            [parallel]
  |--- v3.5 (Protocol)          [mostly parallel -- most phases need v3.0 only; edge crates need v3.1]
  v3.5 ---> v3.6 (Platform) ---> v3.7 (Strategic) ---> v3.8 (Spec Alignment) ---> v3.9 (Remediation) ---> v3.10 (HTTP Contract Completion) ---> v3.11 (Entrypoint + Body Integrity)
```

v4.0 (WASM Guard Runtime)    [parallel with v2.83 -- no dependency on v3.x chain]

v2.80 gates v2.81 and v2.82. v2.81 and v2.82 can execute in parallel.
v2.83 follows v2.81. v3.0 follows v2.83.
v3.1, v3.2, v3.3, v3.4, and most of v3.5 can execute in parallel after v3.0.
v3.5 Phase 341 (A2A/ACP edge crates) depends on v3.1 for signed receipts.
v3.6 and v3.7 are sequential after v3.5. v3.8 documents the shipped v3.x
surface. v3.9 remediates the first wave of correctness and contract gaps
surfaced by the post-implementation audit. v3.10 closes the remaining HTTP
sidecar and cross-SDK substrate gaps that still blocked external adoption.
v3.11 ships the missing operator entrypoint and closes the remaining
request-body integrity and schema consistency gaps.
v4.0 runs in parallel with v2.83 and the v3.x chain. It depends only on the
Phase 347 skeleton (already shipped in v3.7).

## Latest Completed Milestone

### v2.82 Normative Protocol Specification and Conformance

**Status:** complete locally 2026-04-13; phases `311` through `314` are
implemented, verified, audited, and archived locally.
**Executable phases:** 311-314
**Goal:** Write an implementer-facing wire protocol specification with formal
message schemas, define version negotiation and error taxonomy, produce a
standalone threat model for the agent-kernel-tool boundary, and extend the
conformance suite to cover native ARC protocol behavior.

## Earlier Completed Milestones

### v2.80 Core Decomposition and Async Kernel

**Status:** complete locally 2026-04-13; phases `303` through `306` are
implemented and verified locally.
**Executable phases:** 303-306
**Goal:** Split the 32K-line `arc-core` gravity well into focused crates,
decompose the five mega-files into proper module trees, migrate the kernel to
async `&self` with interior mutability, and clean up dependency hygiene so the
codebase can support concurrent multi-agent operation and faster iteration.

### v2.73 Formal Verification

**Status:** complete locally 2026-04-13; phases `299` through `302` are
implemented, verified, audited, and archived locally.
**Executable phases:** 299-302
**Goal:** Complete the Lean 4 formal verification tree by filling all bounded
`sorry` placeholders, proving the core capability and receipt invariants ARC
already claims, and wiring the proof build into CI.

### v2.72 Distributed Systems and Federation

**Status:** complete locally 2026-04-13; phases `295` through `298` are
implemented and verified locally.
**Executable phases:** 295-298
**Goal:** Upgrade trust-control from single-node to Raft-replicated consensus,
enable permissionless federation with anti-sybil controls, and automate
identity lifecycle via SCIM for multi-region production deployments.

### v2.66-v2.70 Ship Readiness Ladder

**Status:** complete locally 2026-04-12; ship readiness phases 273-290 are
implemented and verified locally (v2.69 hosted release gap accepted).
**Goal:** Fill test gaps, harden kernel panics, add quality infrastructure,
observe CI, and package for developer experience.
