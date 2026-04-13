# Requirements: ARC

**Defined:** 2026-03-27
**Latest completed milestone:** v2.68 Quality Infrastructure
(completed locally 2026-04-12)
**Active milestone:** v2.69 CI Gate and Release Qualification
**Planned milestones:** v2.70-v2.73 (Ship Readiness Roadmap)
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

Hosted-observation note: the repo-side fixes and local signed qualification
bundle now exist, but these checkboxes remain open until the updated commit is
rerun in GitHub Actions and the release candidate is tagged from a green
hosted run.

- [ ] **CI-01**: ci.yml runs green in hosted GitHub Actions on stable Rust and MSRV
- [ ] **CI-02**: release-qualification.yml runs green in hosted GitHub Actions
- [ ] **CI-03**: Conformance wave 1-5 all pass across JS, Python, Go peers in hosted environment
- [ ] **CI-04**: qualify-release.sh produces signed qualification artifacts in hosted CI
- [ ] **CI-05**: Release candidate is tagged after hosted observation confirms all gates green

### v2.70 Developer Experience and Packaging

- [ ] **DX-01**: Multi-stage Dockerfile produces minimal Alpine-based arc CLI image
- [ ] **DX-02**: Docker Compose example wraps an MCP server with ARC policy enforcement
- [ ] **DX-03**: Working example shows arc mcp serve as tool provider for Claude via Anthropic SDK
- [ ] **DX-04**: Working example wraps ARC-governed tool server as a LangChain tool
- [ ] **DX-05**: README updated with container quickstart, framework examples, and 5-minute-to-production path

### v2.71 Web3 Live Activation

- [ ] **WEB3-01**: ARC contracts deployed to Base Sepolia testnet
- [ ] **WEB3-02**: End-to-end flow runs: capability -> tool call -> receipt -> settlement with test tokens
- [ ] **WEB3-03**: OpenTimestamps super-root aggregation wired into integration tests
- [ ] **WEB3-04**: Solana memo publication added to conformance harness
- [ ] **WEB3-05**: Cross-chain proof bundle verification passes across EVM, Bitcoin, and Solana lanes
- [ ] **WEB3-06**: Multi-chain qualification report documents all three chains working
- [ ] **WEB3-07**: Operator runbook covers enabling and monitoring web3 settlement

### v2.72 Distributed Systems and Federation

- [ ] **DIST-01**: Trust-control service supports Raft-based consensus replication
- [ ] **DIST-02**: Raft implementation handles split-brain, log compaction, and snapshot transfer
- [ ] **DIST-03**: Operators can publish open-admission federation policies with anti-sybil controls
- [ ] **DIST-04**: Reputation-gated federation entry is supported
- [ ] **DIST-05**: SCIM 2.0 endpoint supports automatic provisioning from external IdP
- [ ] **DIST-06**: SCIM 2.0 endpoint supports automatic deprovisioning from external IdP
- [ ] **DIST-07**: Trust-control deployed across 3 regions proves consistency under network partition
- [ ] **DIST-08**: Replication lag is measured and documented under partition scenarios

### v2.73 Formal Verification

- [ ] **FORMAL-01**: Every sorry placeholder in Lean 4 tree is inventoried and classified
- [ ] **FORMAL-02**: Attenuation monotonicity is proven in Lean 4
- [ ] **FORMAL-03**: Delegation chain integrity is proven in Lean 4
- [ ] **FORMAL-04**: Budget non-negative invariant is proven in Lean 4
- [ ] **FORMAL-05**: Merkle inclusion soundness is proven in Lean 4
- [ ] **FORMAL-06**: Checkpoint consistency is proven in Lean 4
- [ ] **FORMAL-07**: Receipt immutability is proven in Lean 4
- [ ] **FORMAL-08**: Lean 4 lake build runs in CI and fails on any new sorry in proven modules

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
| CI-01 | Phase 284 | Blocked on hosted |
| CI-02 | Phase 284 | Blocked on hosted |
| CI-03 | Phase 285 | Blocked on hosted |
| CI-04 | Phase 286 | Blocked on hosted |
| CI-05 | Phase 286 | Blocked on hosted |
| DX-01 | Phase 287 | Pending |
| DX-02 | Phase 287 | Pending |
| DX-03 | Phase 288 | Pending |
| DX-04 | Phase 289 | Pending |
| DX-05 | Phase 290 | Pending |
| WEB3-01 | Phase 291 | Pending |
| WEB3-02 | Phase 291 | Pending |
| WEB3-03 | Phase 292 | Pending |
| WEB3-04 | Phase 293 | Pending |
| WEB3-05 | Phase 293 | Pending |
| WEB3-06 | Phase 294 | Pending |
| WEB3-07 | Phase 294 | Pending |
| DIST-01 | Phase 295 | Pending |
| DIST-02 | Phase 295 | Pending |
| DIST-03 | Phase 296 | Pending |
| DIST-04 | Phase 296 | Pending |
| DIST-05 | Phase 297 | Pending |
| DIST-06 | Phase 297 | Pending |
| DIST-07 | Phase 298 | Pending |
| DIST-08 | Phase 298 | Pending |
| FORMAL-01 | Phase 299 | Pending |
| FORMAL-02 | Phase 300 | Pending |
| FORMAL-03 | Phase 300 | Pending |
| FORMAL-04 | Phase 300 | Pending |
| FORMAL-05 | Phase 301 | Pending |
| FORMAL-06 | Phase 301 | Pending |
| FORMAL-07 | Phase 301 | Pending |
| FORMAL-08 | Phase 302 | Pending |

**Coverage:**
- Ship readiness requirements: 63 total
- Mapped to phases: 63
- Unmapped: 0

## Out of Scope

| Feature | Reason |
|---------|--------|
| WebSocket transport | HTTP event-stream serves the same role |
| gRPC transport | Streamable HTTP is the multi-client surface |
| Agent-framework maintained plugins | Examples only; ARC is transport-layer agnostic by design |
| Mobile SDK | Web-first, CLI-first; mobile later |
| GUI admin dashboard | CLI and HTTP admin endpoints sufficient for operators |

---
*Requirements defined: 2026-03-27*
*Last updated: 2026-04-12 after local v2.69 repo-side verification; hosted observation still pending*

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
- Active requirements: 5
- Mapped to phases: 230
- Unmapped: 0

---
*Requirements defined: 2026-03-27*
*Last updated: 2026-04-03 after activating v2.52 and queueing phases 217-220*
