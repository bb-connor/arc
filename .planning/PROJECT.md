# Chio

## What This Is

Chio (Chio) is the protocol and trust-control plane for
deterministic, attested agent access to tools, resources, and cross-agent
workflows. The shipped codebase is now Chio-first, with only a small number of
explicitly deprecated Pact-era compatibility shims retained where transition
safety still matters. Chio combines capability-based security, cryptographic
receipts, governed economics, portable trust, and cross-org evidence exchange
so operators can prove what an agent was allowed to do, what it actually did,
and how that activity should be trusted across boundaries.

## Core Value

Chio must provide deterministic, least-privilege agent authority with auditable
outcomes, bounded spend, and cryptographic proof artifacts that enable economic
security, regulatory compliance, and portable trust.

## Current State

**Latest completed milestone:** v3.18 Bounded Chio Ship Readiness Closure
(completed locally 2026-04-15; pending archival)
**Latest archived milestone:** v3.14 Universal Fabric and Kernel Convergence
(completed locally and archived locally 2026-04-14)
**Most recent implemented milestone:** Post-v3.18 Chio Closure Program
(completed locally 2026-04-19; tracker fully green through the final release-truth sync gate)
**Active milestone:** none; `v3.18` remains the latest ship lane and is complete locally pending archival
**Parallel milestone:** v4.0 WASM Guard Runtime Completion (phases 373-376)
**Deferred milestone:** v2.71 Web3 Live Activation (pending external Base
Sepolia credentials, reviewed live-chain artifacts, and OTS tooling)
**Planned milestones:** v3.0 through v3.18 (Universal Security Kernel era)
**Planned milestones:** v4.0 through v4.2 (WASM Guard Plugin Ecosystem)
**Next GSD action:** `$gsd-complete-milestone` for `v3.18`, then stage hosted release observation on the bounded candidate

## Current Milestone: v3.18 Bounded Chio Ship Readiness Closure

**Goal:** Convert the Track A P0 blocker list into one executable bounded-ship
closure lane so Chio can ship one honest, pristine bounded release without
overclaiming stronger delegation, attestation, non-repudiation, HA, or
market-position properties.

**Target features:**
- one coherent bounded-Chio claim surface across README, release docs, review
  docs, and planning state
- one explicit runtime boundary for delegated authority and governed
  provenance so ship-facing docs stop implying stronger semantics than the
  kernel enforces
- one named hosted/auth security profile for the recommended bounded release,
  with compatibility-only paths clearly demoted
- one named bounded operational profile for trust-control, budgets, and
  receipts that excludes consensus-grade HA, distributed-linearizable spend,
  and transparency-log semantics
- one authoritative pre-ship checklist and bounded qualification gate

**Execution status:** phases `417` through `421` are complete locally.
`v3.18` is now the latest completed milestone and closes the Track A P0
bounded-ship blockers by making bounded Chio the only ship-facing release
boundary. The retained repo-local decision from `v3.17` still stands: Chio is
comptroller-capable software, not yet a proved market position. The
post-`v3.18` closure tracker also completed locally on 2026-04-19: portable
browser qualification, CI and release gating, frozen runtime-semantics docs,
and the final release-truth sync gate are all green in
`.planning/POST_V3_18_EXECUTION_TRACKER.md`.

## v4.x WASM Guard Plugin Ecosystem

**Strategic continuation of v3.7.** Phase 347 shipped the WASM guard scaffold
(ABI, wasmtime backend, fuel metering, mock tests). v4.x completes the
"policy-as-code in any language" vision through three milestones.

| Milestone | Name | Phases | Focus |
|-----------|------|--------|-------|
| v4.0 | WASM Guard Runtime Completion | 373-376 | Host-side hardening, manifest, enriched request, startup wiring, benchmarks |
| v4.1 | Guard SDK and Developer Experience | 382-385 | Rust guest SDK, proc macro, CLI tooling, test fixtures |
| v4.2 | WIT Migration and Multi-Language SDKs | 386-389 | Component Model, TypeScript/Python/Go guest SDKs, conformance |

**Design docs:** `docs/guards/01-05` (current guard system, WASM runtime
landscape, long-range roadmap, HushSpec/ClawdStrike integration, v1 decisions)

## Current Milestone Status

`v3.13 Universal Orchestration Closure` and `v3.14 Universal Fabric and
Kernel Convergence` are complete and archived locally. `v3.15 Universal
Protocol Fabric Realization`, `v3.16 Universal Control-Plane Thesis`,
`v3.17 Comptroller Market Position Proof`, and `v3.18 Bounded Chio Ship
Readiness Closure` are complete locally and pending archival. The follow-on
post-`v3.18` closure tracker is also complete locally. Their combined result is
that Chio can now honestly claim a bounded ship-ready Chio release on repo-local
evidence while keeping the stronger control-plane and comptroller-capable
claims explicitly secondary. `v4.0` remains a parallel strategic bet, while
`v2.83` remains older prior-lane debt rather than an archived milestone.

## v3.x Universal Security Kernel Era

**Strategic pivot:** Chio expands from protocol adapter collection to universal
security kernel for the agent economy. One kernel, many substrates. Signed
receipts across HTTP APIs, agent protocols, and framework middleware.

**19 milestones:** v3.0 through v3.18, from foundation through bounded ship
readiness closure.
**Dependency chain:** v3.0 -> v3.1 (parallel with v3.2) -> v3.3 -> v3.4 ->
v3.5 -> v3.6 -> v3.7 -> v3.8 -> v3.9 -> v3.10 -> v3.11 -> v3.12 -> v3.13 ->
v3.14 -> v3.15 -> v3.16 -> v3.17 -> v3.18

| Milestone | Name | Phases | Focus |
|-----------|------|--------|-------|
| v3.0 | Universal Security Kernel Foundation | 319-322 | chio-http-core, chio-openapi, arc.yaml, arc api protect |
| v3.1 | Attestation Completion | 323-326 | ACP kernel integration, compliance certs, OTel export |
| v3.2 | Python Adoption | 327-330 | chio-sdk-python, chio-asgi, chio-fastapi, chio-langchain |
| v3.3 | TypeScript Adoption | 331-334 | @chio-protocol/node-http, Express/Fastify/Elysia wrappers |
| v3.4 | Guard Expansion | 335-338 | Session journal, post-invocation hooks, deterministic guards |
| v3.5 | Protocol Breadth | 339-342 | MCP completion, OpenAPI-to-MCP bridge, A2A/ACP edges |
| v3.6 | Platform Extensions | 343-346 | Go SDK, K8s controller/injector, chio-tower, JVM, .NET |
| v3.7 | Strategic Bets | 347-350 | WASM guards, economics/metering, AG-UI, skill/workflow authority |
| v3.8 | Normative Specification Alignment | 351-358 | Spec docs, JSON schemas, SDK refs, design doc reconciliation |
| v3.9 | Runtime Correctness and Contract Remediation | 359-363 | OpenAI/kernel fix, certificate wire format, adapter validation, flake cleanup |
| v3.10 | HTTP Sidecar and Cross-SDK Contract Completion | 364-367 | Rust sidecar endpoints, Python substrate migration, cross-SDK capability alignment |
| v3.11 | Sidecar Entrypoint and Body-Integrity Completion | 368-372 | `arc api protect` CLI, body-preserving middleware, raw-byte hashing, schema cleanup |
| v3.12 | Cross-Protocol Integrity and Truth Completion | 377-381 | ACP crypto enforcement, outward-edge kernel mediation, operational parity, repo-truth reconciliation |
| v3.13 | Universal Orchestration Closure | 390-396 | generic orchestrator, edge unification, fidelity gating, ledger reconciliation, HTTP/runtime convergence, lifecycle closure, claim upgrade |
| v3.14 | Universal Fabric and Kernel Convergence | 397-402 | protocol-to-protocol fabric, literal kernel convergence, SDK evidence parity, lifecycle-equivalent mediation, archival truth, full-vision claim decision |
| v3.15 | Universal Protocol Fabric Realization | 403-406 | protocol-aware binding/registry, lifecycle completion, final v3 truth closure, full-vision requalification |
| v3.16 | Universal Control-Plane Thesis | 407-412 | universal registry routing, dynamic control plane, ecosystem proof, final thesis gate |
| v3.17 | Comptroller Market Position Proof | 413-416 | external operator surfaces, partner-visible settlement contracts, federated proof, market-position gate |
| v3.18 | Bounded Chio Ship Readiness Closure | 417-421 | claim/planning truth, delegation boundary, hosted/auth profile truth, provenance truth, bounded release gate |

## Foundation and Adoption Ladder (v2.80-v2.83)

Four milestones shifting focus from internal feature expansion to structural
quality, external usability, protocol specification, and production hardening.
Dependencies: v2.80 -> v2.81 + v2.82 (parallel) -> v2.83.

| Milestone | Name | Phases | Focus |
|-----------|------|--------|-------|
| v2.80 | Core Decomposition and Async Kernel | 303-306 | Split chio-core, decompose mega-files, async kernel, dep hygiene |
| v2.81 | Deployable Chio and Developer Onboarding | 307-310 | Naming fix, SDKs, Docker experience, tutorial |
| v2.82 | Normative Protocol Specification and Conformance | 311-314 | Wire spec, error taxonomy, threat model, conformance |
| v2.83 | Coverage, Hardening, and Production Qualification | 315-318 | Integration tests, 80% coverage, store hardening, structured errors |

## Ship Readiness Ladder (v2.66-v2.73)

Eight milestones closing the gap between production-candidate and production release.
Dependencies: v2.66+v2.67+v2.68 parallel -> v2.69 -> v2.70 -> v2.71+v2.72+v2.73 parallel.

| Milestone | Name | Phases | Focus |
|-----------|------|--------|-------|
| v2.66 | Test Coverage for Untested Crates | 273-276 | Fill test gaps in chio-hosted-mcp, chio-wall, chio-siem |
| v2.67 | Kernel Panic Hardening | 277-280 | Convert 22 kernel panics to typed errors |
| v2.68 | Quality Infrastructure | 281-283 | Property tests, benchmarks, code coverage |
| v2.69 | CI Gate and Release Qualification | 284-286 | Observe hosted CI green, tag release |
| v2.70 | Developer Experience and Packaging | 287-290 | Docker, framework examples, quickstart |
| v2.71 | Web3 Live Activation | 291-294 | Testnet settlement, BTC/SOL anchoring |
| v2.72 | Distributed Systems and Federation | 295-298 | Raft consensus, permissionless federation, SCIM |
| v2.73 | Formal Verification | 299-302 | Complete Lean 4 proofs, CI integration |

`v2.5` through `v2.8` executed the rename, governed-economics, portable-trust,
and launch-closure ladder derived from `docs/research/DEEP_RESEARCH_1.md`.
Chio now sits at a locally qualified launch package with hosted workflow
observation still required before external publication, plus completed
economic-interop, underwriting, portable credential, verifier-side OID4VP,
multi-cloud attestation, and enterprise-IAM profile layers. Chio now ships a
normative authorization profile, sender-constrained discovery semantics,
machine-readable profile metadata, reviewer packs tied back to signed receipt
truth, fail-closed qualification over malformed sender, assurance, and
delegated-call-chain projection, plus a governed public certification
marketplace surface with versioned evidence profiles, public metadata,
search/transparency, and dispute-aware consumption semantics. Chio now also
ships signed exposure, scorecard, facility, credit-backtest,
provider-risk-package, reserve-state bond artifacts, immutable bond-loss
lifecycle state, and one bonded-execution simulation lane with explicit
operator control policy from `v2.18` and `v2.19`. Chio now also ships one
curated liability-provider registry with signed provider-policy artifacts and
fail-closed jurisdiction or coverage resolution, plus canonical quote-request,
quote-response, placement, and bound-coverage artifacts over one signed risk
package, plus immutable claim-package, provider-response, dispute, and
adjudication artifacts, with `v2.20` now closing the liability-market ladder
locally through marketplace qualification and partner-proof boundary updates.
The post-`v2.20` endgame ladder is now complete locally through `v2.28`.
Chio now has a bounded standards-native, assurance-federated, live-capital,
open-registry, and adversarially qualified open-market control plane with
explicit residual non-goals instead of a partially normalized research plan.
That endgame ladder remains normalized in
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md`.
The post-`v2.28` maximal-endgame ladder was captured in
`.planning/research/POST_V2_28_MAXIMAL_ENDGAME_ROADMAP.md` and is now fully
consumed locally.
`v2.29` is now complete locally with one machine-readable extension
inventory, one official Chio stack package, one fail-closed extension
manifest and negotiation contract, and one qualification matrix that later
web3/live-money work can consume without redefining Chio truth. `v2.30` is now
also complete locally with one official web3 trust profile, contract package,
chain configuration, anchor-proof and oracle-evidence substrate, and one
bounded settlement-dispatch plus execution-receipt contract that reconciles
real external rail behavior back to Chio truth. `v2.31` is now also complete
locally with one bounded autonomous pricing-input, authority-envelope,
pricing-decision, capital-pool optimization, execution, rollback, drift, and
qualification surface over that explicit web3 and capital substrate. `v2.32`
is now also complete locally with one bounded federation-activation exchange,
quorum-report, open-admission-policy, shared reputation-clearing, and
qualification surface over the generic registry, governance, open-market, and
portable-reputation substrate. `v2.33` is now also complete locally with one
bounded public identity profile, wallet-directory, wallet-routing, and
identity-interop qualification surface over the existing passport, verifier,
discovery, and federation substrate. That maximal-endgame ladder is complete,
but it closed at the bounded artifact and contract boundary rather than the
full runtime realization described in the late-March 2026 web3 research set.
Chio now also completes `v2.34` locally with one packaged Solidity contract
family, compiled artifacts, Base/Arbitrum deployment templates, local-devnet
qualification, measured gas/security release evidence, and one Alloy binding
crate for the official web3 runtime substrate. Chio now also completes `v2.35`
locally with one bounded `chio-link` oracle runtime and completes `v2.36`
locally with one bounded `chio-anchor` publication, discovery, and proof-bundle
runtime. Chio now also completes `v2.37` locally with one bounded `chio-settle`
runtime over escrow create/release/refund, bond lifecycle calls, explicit
finality or recovery projection, Solana-native settlement preparation, and a
real runtime-devnet qualification lane. Chio now also completes `v2.38`
locally with one bounded Functions fallback, one bounded automation surface,
one bounded CCIP settlement-coordination message family, and one bounded
payment-interop layer for x402, EIP-3009, Circle-managed custody, and
ERC-4337/paymaster compatibility. Chio now also completes `v2.39` locally with
one bounded runtime-operations layer over `chio-link`, `chio-anchor`, and
`chio-settle`, including explicit runtime reports, lane-health and emergency
control semantics, deployment-promotion policy, readiness-audit and
partner-proof packages, and the final protocol/release boundary rewrite that
closes the appended late-March 2026 web3 research ladder honestly.
Chio now also completes `v2.40` locally with deterministic settlement identity,
mandatory checkpoint evidence gates, truthful bond/collateral and oracle
authority semantics, cryptographic Bitcoin secondary-lane verification, and
artifact-derived contract-binding parity qualification across the bounded web3
stack. Chio now also completes `v2.41` locally with hosted qualification,
reviewed promotion, exercised operator controls, and partner-visible end-to-end
settlement proof, and completes `v2.42` locally with authoritative release
truth, planning/tooling integrity, assurance backfill, and runtime boundary
decomposition. `v2.43 MERCURY Evidence Productization Foundation` is now also
complete locally, including the corrective `184.1` boundary-extraction phase
that keeps Mercury as an app on Chio rather than an `arc` subcommand.
After `v2.43`, the repo executed `v2.44 MERCURY Supervised-Live Bridge and
Controlled Productionization`. That milestone kept the same controlled
release, rollback, and inquiry workflow, moved it from replay/shadow toward
supervised-live use, and explicitly forbade broad connector or workflow
expansion before the same workflow proved sticky in controlled production.
Phase `185` is now complete locally: the same-workflow bridge, the human
operating envelope, and the proceed/defer/stop decision artifact are frozen in
the Mercury docs. Phase `186` is now also complete locally: `chio-mercury-core`
and `chio-mercury` now accept typed supervised-live captures in `live` or
`mirrored` mode and export them through the same Chio evidence, proof, and
inquiry contracts as the pilot path. Phase `187` is now also complete locally:
supervised-live capture now carries explicit release/rollback gates,
evidence-health state, coverage state, and interruption records; export fails
closed when that control state is unsafe; and the Mercury docs now include one
canonical supervised-live operations runbook. Phase `188` can now focus on the
partner-facing qualification corpus and bridge-close artifact without reopening
scope or safety posture. Phase `188` is now also complete locally:
`mercury supervised-live qualify` generates the canonical reviewer package and
qualification report, the bridge now closes with one explicit `proceed`
decision artifact, and later governance, downstream-consumer, connector, and
OEM tracks remain deferred. `v2.44` now has all four phases complete locally
and has now passed milestone audit with the same-workflow reviewer package and
explicit bridge-close decision archived under `.planning/milestones/`. After
`v2.44`, the repo executed
`v2.45 MERCURY Downstream Review Distribution and Assurance Packaging`. That
milestone kept expansion limited to one downstream archive/review/case-
management consumer and one reviewer-assurance delivery path over the same
proof and inquiry contracts. Phase `189` is now complete locally: the Mercury
docs freeze one downstream `case_management_review` lane, its owner, delivery
mode, and explicit non-goals. Phase `190` is now also complete locally:
`chio-mercury-core` defines one downstream review package profile and one
assurance-package family rooted in existing proof, inquiry, reviewer, and
qualification artifacts. Phase `191` is now also complete locally:
`chio-mercury` exports one bounded downstream review package, consumer
manifest, delivery acknowledgement, and paired internal/external assurance
packages over that single consumer lane. Phase `192` is now also complete
locally: `mercury downstream-review validate` generates the downstream
validation bundle, writes the explicit `proceed_case_management_only`
decision artifact, and the Mercury docs now define the operating model and
recovery posture for that lane. `v2.45` now has all four phases complete
locally and has now passed milestone audit with downstream review artifacts
and milestone snapshots archived under `.planning/milestones/`. After
`v2.45`, the repo executed
`v2.46 MERCURY Governance Workbench Approval, Release, and Exception
Controls`. That milestone kept expansion limited to one governance-workbench
workflow over the same evidence and publication model, covering governed
change review plus bounded release, rollback, approval, and exception control
without widening into multiple downstream connectors, OEM packaging,
trust-network work, or deep runtime coupling. Phase `193` is now complete
locally: the Mercury docs freeze one governance-workbench
`change_review_release_control` path, one workflow owner, one control-team
owner, and explicit non-goals. Phase `194` is now also complete locally:
`chio-mercury-core` defines one governance decision package and one bounded
review-package family for workflow-owner and control-team audiences over the
same proof and qualification artifacts. Phase `195` is now also complete
locally: `chio-mercury` exports one bounded governance-workbench package with
explicit control-state, workflow-owner/control-team review packages, and
fail-closed behavior rooted in the existing Mercury proof chain. Phase `196`
is now also complete locally: `mercury governance-workbench validate`
generates the governance validation bundle, writes the explicit
`proceed_governance_workbench_only` decision artifact, and the Mercury docs
now define the operating model and support boundary for that lane. `v2.46`
now has all four phases complete locally and has now passed milestone audit
with governance-workbench artifacts and milestone snapshots archived under
`.planning/milestones/`. `v2.47` is now also complete locally: Mercury ships
one bounded assurance-suite lane for internal, auditor, and counterparty
reviewer packaging over the same proof, qualification, and governance
artifacts, one repo-native `mercury assurance-suite export` / `validate`
surface, one reviewer operating model, and one explicit
`proceed_assurance_suite_only` decision. `v2.47` now has all four phases
complete locally and has now passed milestone audit with assurance-suite
artifacts and milestone snapshots archived under `.planning/milestones/`.
`v2.48 MERCURY Embedded OEM Distribution, Partner Packaging, and Bounded SDK
Surface` is now also complete locally: Mercury ships one bounded
`embedded-oem` lane over the validated assurance suite, one
`reviewer_workbench_embed` partner surface, one `signed_artifact_bundle`
manifest contract, one copied counterparty-review bundle, one partner
operating model, and one explicit `proceed_embedded_oem_only` decision
without widening into multi-partner OEM breadth, trust-network services,
Chio-Wall, or a generic SDK platform. `v2.48` now has all four phases complete
locally and has now passed milestone audit with embedded OEM artifacts and
milestone snapshots archived under `.planning/milestones/`.
`v2.49 MERCURY Trust Network Witness, Publication, and Proof-Profile
Interoperability` is now also complete locally: Mercury ships one bounded
`trust-network` lane over the validated embedded-OEM stack, one
`counterparty_review_exchange` sponsor boundary, one
`chio_checkpoint_witness_chain` trust anchor, one
`proof_inquiry_bundle_exchange` interoperability surface, one shared proof and
inquiry bundle, one explicit operating model, and one explicit
`proceed_trust_network_only` decision without widening into generic
trust-broker services, Chio-Wall, or multi-product platform hardening. `v2.49`
now has all four phases complete locally and has now passed milestone audit
with trust-network artifacts and milestone snapshots archived under
`.planning/milestones/`.
`v2.50 Chio-Wall Companion Product Core, Guard Evidence, and Buyer Motion` is
now also complete locally: Chio-Wall ships as one bounded companion product on
Chio through separate `chio-wall-core` and `chio-wall` crates, one
`control_room_barrier_review` buyer motion, one `tool_access_domain_boundary`
control surface over `research -> execution`, one Chio evidence export path,
one buyer-review package, and one explicit `proceed_arc_wall_only` decision
without widening into MERCURY expansion, generic barrier-platform breadth, or
multi-product hardening. `v2.50` now has all four phases complete locally and
has now passed milestone audit with Chio-Wall artifacts and milestone snapshots
archived under `.planning/milestones/`.
`v2.51 MERCURY Extensions Shared Service Boundaries, Cross-Product
Governance, and Platform Hardening` is now complete locally, but its Chio-side
`product-surface` command direction was too coupled to the current Mercury
and Chio-Wall product set. `v2.52 MERCURY Extensions Chio Purity Restoration,
Boundary Cleanup, and Qualification` is now also complete locally: Chio no
longer exposes product-specific `product-surface` entrypoints, Chio's generic
receipt query and trust-control surfaces no longer name Mercury-specific
filters, and Chio's SQLite receipt store no longer depends on
`chio-mercury-core` or maintain a Mercury-only receipt index. The resulting
boundary is explicit again: Chio stays generic, Mercury stays opinionated, and
Mercury-specific retrieval or packaging concerns stay out of the Chio kernel,
store, and generic CLI.
`v2.53 MERCURY Release Readiness, Partner Delivery, and Controlled Adoption`
is now complete locally. The milestone returns to the Mercury app surface
itself and packages the existing Mercury lanes into one bounded release-
readiness program without reintroducing Mercury-specific logic into Chio
generic crates. `v2.54 MERCURY Controlled Adoption, Renewal Evidence, and
Reference Readiness` is now also complete locally: Mercury ships one bounded
post-launch adoption lane over the existing release-readiness stack, one
controlled-adoption export and validate surface, one renewal-evidence bundle,
one customer-success and reference-readiness operating model, and one explicit
`scale_controlled_adoption_only` decision without widening Mercury into new
delivery surfaces or pulling product logic back into Chio generic crates.
`v2.55 MERCURY Reference Distribution, Landed-Account Expansion, and Claim
Discipline` is now also complete locally: Mercury ships one bounded
reference-distribution export and validate surface, one landed-account
account-motion freeze, one claim-discipline and buyer-approval model, one
sales-handoff brief, and one explicit
`proceed_reference_distribution_only` decision without widening into generic
sales tooling, merged shells, or Chio commercial surfaces. `v2.56 MERCURY
Broader Distribution Readiness, Selective Account Qualification, and Claim
Governance` is now also complete locally: Mercury ships one bounded
`broader-distribution` export and validate surface, one selective-account
target freeze, one claim-governance and approval model, one distribution-
handoff brief, and one explicit `proceed_broader_distribution_only`
decision without widening into generic sales tooling, CRM workflows, merged
shells, or Chio commercial surfaces. `v2.57 MERCURY Selective Account
Activation, Controlled Delivery, and Claim Containment` is now also complete
locally: Mercury exports one bounded selective-account-activation package,
one controlled-delivery bundle, one claim-containment and approval-refresh
path, one customer-handoff brief, one validation report, and one explicit
`proceed_selective_account_activation_only` decision without widening into
generic onboarding tooling, CRM workflows, channel marketplaces, merged
shells, or Chio commercial surfaces.
`v2.60 MERCURY Second-Account Expansion Qualification, Portfolio Boundary,
and Reuse Governance` is now also complete locally: Mercury exports one
bounded second-account-expansion package, one portfolio-review bundle, one
expansion-approval artifact, one reuse-governance artifact, one explicit
second-account handoff, one validation report, and one explicit
`proceed_second_account_expansion_only` decision without widening into
generic customer-success tooling, account-management platforms, revenue
operations systems, multi-account portfolio programs, or Chio commercial
surfaces.
`v2.61 MERCURY Portfolio Program Qualification, Multi-Account Boundary, and
Revenue Operations Guardrails` is now also complete locally: Mercury exports
one bounded portfolio-program package, one program-review bundle, one
portfolio-approval artifact, one revenue-operations-guardrails artifact, one
explicit program handoff, one validation report, and one explicit
`proceed_portfolio_program_only` decision without widening into generic
account-management tooling, revenue operations systems, forecasting stacks,
billing platforms, channel programs, or Chio commercial surfaces.
`v2.62 MERCURY Second Portfolio Program Qualification, Reuse Discipline, and
Revenue Boundary` is now also complete locally: Mercury exports one bounded
second-portfolio-program package, one portfolio-reuse bundle, one portfolio-
reuse approval artifact, one revenue-boundary-guardrails artifact, one
explicit second-program handoff, one validation report, and one explicit
`proceed_second_portfolio_program_only` decision without widening into generic
portfolio-management tooling, revenue operations systems, forecasting stacks,
billing platforms, channel programs, or Chio commercial surfaces.
`v2.63`, `v2.64`, and `v2.65` are now also complete locally: Mercury exports
one bounded `third_program` lane, one bounded `program_family` lane, and one
bounded `portfolio_revenue_boundary` lane over the same dedicated Mercury app
surface, each with product-owned approval or handoff artifacts, real export
and validation bundles, and one explicit proceed decision, without reopening
Chio generic boundary work.

## Latest Roadmap Closure

### v2.65 MERCURY Portfolio Revenue Boundary Qualification, Commercial Handoff, and Channel Boundary

**Goal:** Qualify one bounded Mercury portfolio-revenue-boundary lane over the
existing program-family package so Mercury can prove one named commercial
handoff can consume program-family evidence without widening into generic
revenue operations systems, forecasting stacks, billing platforms, channel
programs, merged shells, or Chio commercial surfaces.

**Executable phase status:**
- Phase 269 complete: Mercury revenue boundary scope lock and commercial
  handoff freeze
- Phase 270 complete: Mercury revenue boundary package and commercial review
  contract
- Phase 271 complete: Mercury commercial approval, channel boundary rules,
  and handoff
- Phase 272 complete: Mercury revenue boundary validation, proceed decision,
  and boundary

### v2.64 MERCURY Program Family Qualification, Shared Review Package, and Portfolio Claim Discipline

**Goal:** Qualify one bounded Mercury program-family lane over the existing
third-program package so Mercury can prove one explicitly named small program
family can be reviewed together without widening into generic portfolio-
management tooling, revenue operations systems, forecasting stacks, billing
platforms, channel programs, merged shells, or Chio commercial surfaces.

**Executable phase status:**
- Phase 265 complete: Mercury program family scope lock and shared review
  boundary freeze
- Phase 266 complete: Mercury program family package and shared review
  contract
- Phase 267 complete: Mercury program family approval, portfolio claim
  discipline, and family handoff
- Phase 268 complete: Mercury program family validation, proceed decision,
  and boundary

### v2.63 MERCURY Third Program Qualification, Reuse Repeatability, and Multi-Program Boundary

**Goal:** Qualify one bounded Mercury third-program lane over the existing
second-portfolio-program package so Mercury can prove one evidence-backed
multi-account program family can support one additional adjacent program reuse
decision without widening into generic portfolio-management tooling, revenue
operations systems, forecasting stacks, billing platforms, channel programs,
merged shells, or Chio commercial surfaces.

**Executable phase status:**
- Phase 261 complete: Mercury third program scope lock and repeatability
  boundary freeze
- Phase 262 complete: Mercury third program package and repeated portfolio
  reuse contract
- Phase 263 complete: Mercury third-program approval refresh, multi-program
  guardrails, and handoff
- Phase 264 complete: Mercury third program validation, proceed decision, and
  boundary

### v2.62 MERCURY Second Portfolio Program Qualification, Reuse Discipline, and Revenue Boundary

**Goal:** Qualify one bounded Mercury second-portfolio-program lane over the
existing portfolio-program package so Mercury can prove one evidence-backed
multi-account program can support one adjacent program reuse decision without
widening into generic portfolio-management tooling, revenue operations
systems, forecasting stacks, billing platforms, channel programs, merged
shells, or Chio commercial surfaces.

**Executable phase status:**
- Phase 257 complete: Mercury second portfolio program scope lock and reuse
  boundary freeze
- Phase 258 complete: Mercury second portfolio program package and portfolio
  reuse contract
- Phase 259 complete: Mercury portfolio reuse approval, revenue boundary
  guardrails, and second-program handoff
- Phase 260 complete: Mercury second portfolio program validation, proceed
  decision, and boundary

### v2.61 MERCURY Portfolio Program Qualification, Multi-Account Boundary, and Revenue Operations Guardrails

**Goal:** Qualify one bounded Mercury portfolio-program lane over the
existing second-account-expansion package so Mercury can prove one renewed
workflow can support one explicitly governed multi-account program without
widening into generic customer-success tooling, account-management
platforms, revenue operations systems, channel marketplaces, merged shells,
or Chio commercial surfaces.

**Executable phase status:**
- Phase 253 complete: Mercury portfolio program scope lock and multi-account
  boundary freeze
- Phase 254 complete: Mercury portfolio program package and program review
  contract
- Phase 255 complete: Mercury portfolio approval, revenue operations
  guardrails, and program handoff
- Phase 256 complete: Mercury portfolio program validation, proceed decision,
  and boundary

### v2.60 MERCURY Second-Account Expansion Qualification, Portfolio Boundary, and Reuse Governance

**Goal:** Qualify one bounded Mercury second-account expansion lane over the
existing renewal-qualification package so Mercury can prove one renewed
account can support one adjacent account expansion decision without widening
into generic customer-success tooling, account-management platforms,
multi-account renewal programs, channel marketplaces, merged shells, or Chio
commercial surfaces.

**Executable phase status:**
- Phase 249 complete: Mercury second-account expansion scope lock and
  portfolio boundary freeze
- Phase 250 complete: Mercury expansion-readiness package and portfolio
  review contract
- Phase 251 complete: Mercury expansion approval, reuse governance, and
  second-account handoff
- Phase 252 complete: Mercury expansion validation, proceed decision, and
  boundary

### v2.59 MERCURY Renewal Qualification, Outcome Review, and Expansion Boundary

**Goal:** Qualify one bounded Mercury renewal lane over the existing delivery-
continuity package so Mercury can prove one activated account can cross one
evidence-backed renewal decision boundary without widening into generic
customer-success tooling, CRM workflows, account-management platforms, channel
marketplaces, merged shells, or Chio commercial surfaces.

**Executable phase status:**
- Phase 245 complete: Mercury renewal qualification scope lock and renewal
  boundary freeze
- Phase 246 complete: Mercury renewal package and outcome review contract
- Phase 247 complete: Mercury renewal approval, reference reuse discipline,
  and expansion boundary handoff
- Phase 248 complete: Mercury renewal validation, renew decision, and
  boundary

### v2.58 MERCURY Controlled Delivery Continuity, Outcome Evidence, and Renewal Gate

**Goal:** Qualify one bounded Mercury controlled-delivery continuity lane
over the existing selective-account-activation package so Mercury can prove
one activated account remains evidence-backed, renewal-gated, and supportable
without widening into generic onboarding tooling, CRM workflows, support
desks, channel marketplaces, or Chio commercial surfaces.

**Executable phase status:**
- Phase 241 complete: Mercury controlled delivery continuity scope lock and
  account boundary freeze
- Phase 242 complete: Mercury delivery continuity package and outcome evidence
  contract
- Phase 243 complete: Mercury renewal gate, delivery escalation, and customer
  evidence handoff
- Phase 244 complete: Mercury controlled delivery continuity validation,
  renewal decision, and boundary

### v2.57 MERCURY Selective Account Activation, Controlled Delivery, and Claim Containment

**Goal:** Qualify one bounded Mercury selective-account activation lane over
the existing broader-distribution package so Mercury can move one governed
qualified account into controlled delivery without widening into generic
onboarding tooling, CRM workflows, channel marketplaces, merged shells, or
Chio commercial surfaces.

**Executable phase status:**
- Phase 237 complete: Mercury selective-account activation scope lock and
  delivery freeze
- Phase 238 complete: Mercury activation package and controlled delivery
  contract
- Phase 239 complete: Mercury claim containment, activation approval refresh,
  and customer handoff
- Phase 240 complete: Mercury selective-account activation validation,
  proceed decision, and boundary

### v2.56 MERCURY Broader Distribution Readiness, Selective Account Qualification, and Claim Governance

**Goal:** Qualify one bounded Mercury broader-distribution lane over the
existing reference-distribution package so Mercury can use one approved
reference-backed bundle to support selective account qualification without
widening into generic sales tooling, CRM workflows, merged shells, or Chio
commercial surfaces.

**Executable phase status:**
- Phase 233 complete: Mercury broader-distribution scope lock and target-
  account freeze
- Phase 234 complete: Mercury qualification package and governed distribution
  contract
- Phase 235 complete: Mercury claim governance, selective account approval,
  and distribution handoff
- Phase 236 complete: Mercury broader-distribution validation, proceed
  decision, and boundary

### v2.55 MERCURY Reference Distribution, Landed-Account Expansion, and Claim Discipline

**Goal:** Qualify one bounded Mercury reference-distribution and landed-
account expansion lane over the existing controlled-adoption package so
Mercury can turn one referenceable win into a repeatable expansion motion
without widening into generic sales tooling, merged shells, or Chio generic
commercial surfaces.

**Executable phase status:**
- Phase 229 complete: Mercury reference expansion scope lock and account-motion
  freeze
- Phase 230 complete: Mercury reference package and expansion evidence contract
- Phase 231 complete: Mercury claim discipline, buyer-reference approval, and
  sales handoff
- Phase 232 complete: Mercury reference expansion validation, proceed
  decision, and boundary

### v2.54 MERCURY Controlled Adoption, Renewal Evidence, and Reference Readiness

**Goal:** Qualify one bounded post-launch Mercury adoption lane over the
existing release-readiness package so Mercury can prove renewal and reference
readiness without widening into new product lines, merged shells, or Chio
generic release surfaces.

**Executable phase status:**
- Phase 225 complete: Mercury controlled adoption scope lock and cohort freeze
- Phase 226 complete: Mercury adoption evidence and renewal package contract
- Phase 227 complete: Mercury customer success, reference readiness, and
  support escalation
- Phase 228 complete: Mercury controlled adoption validation, scale decision,
  and expansion boundary

### v2.53 MERCURY Release Readiness, Partner Delivery, and Controlled Adoption

**Goal:** Package Mercury's dedicated app surface into one bounded
release-readiness lane over the existing pilot, supervised-live, downstream,
governance, assurance, embedded-OEM, and trust-network artifacts without
pulling product logic back into Chio or widening into a new product line.

**Executable phase status:**
- Phase 221 complete: Mercury release readiness scope lock and boundary freeze
- Phase 222 complete: Mercury reviewer and partner delivery package contract
- Phase 223 complete: Mercury operator release controls, escalation, and
  support handoff
- Phase 224 complete: Mercury release-readiness validation, launch decision,
  and expansion boundary

### v2.52 MERCURY Extensions Chio Purity Restoration, Boundary Cleanup, and Qualification

**Goal:** Restore Chio's generic substrate boundary by removing product-specific
Mercury and Chio-Wall logic from Chio control-plane, CLI, query, and store
surfaces, then validate the resulting purity pass with low-memory regression
checks.

**Executable phase status:**
- Phase 217 complete: Chio substrate purity boundary correction
- Phase 218 complete: generic receipt query surface cleanup
- Phase 219 complete: SQLite receipt store decoupling from Mercury
- Phase 220 complete: Chio purity validation and milestone closeout

### v2.51 MERCURY Extensions Shared Service Boundaries, Cross-Product Governance, and Platform Hardening

**Goal:** Define the shared-service, release-governance, and trust-material
boundaries across the validated MERCURY and Chio-Wall products on Chio, then
publish one bounded platform-hardening backlog for sustained multi-product
operation without collapsing the products together or widening Chio's generic
substrate.

**Executable phase status:**
- Phase 213 complete: shared service boundary review and product ownership
  freeze
- Phase 214 complete: cross-product governance, release, and trust-material
  operating model
- Phase 215 complete: platform hardening backlog, dependency map, and
  qualification envelope
- Phase 216 complete: multi-product validation, operating decision, and next-
  step boundary

### v2.50 Chio-Wall Companion Product Core, Guard Evidence, and Buyer Motion

**Goal:** Deliver one bounded Chio-Wall companion-product lane on Chio,
reusing the same checkpoint, publication, and verification substrate while
freezing one buyer motion, one information-domain evidence contract, and one
control-path guard surface without turning MERCURY into Chio-Wall or widening
immediately into multi-product hardening.

**Executable phase status:**
- Phase 209 complete: Chio-Wall scope lock and buyer boundary freeze
- Phase 210 complete: information-domain evidence schema and Chio-Wall contract
- Phase 211 complete: control-path guard surface and companion-product
  packaging path
- Phase 212 complete: Chio-Wall validation, buyer packaging, and expansion
  decision

### v2.49 MERCURY Trust Network Witness, Publication, and Proof-Profile Interoperability

**Goal:** Deliver one bounded trust-network lane over the existing MERCURY
proof, inquiry, publication, supervised-live, downstream, governance,
assurance, and embedded-OEM artifacts, covering one shared trust-anchor and
witness continuity contract, one proof-profile interoperability surface, and
one explicit rollout boundary without widening into Chio-Wall, multi-network
trust services, or generic ecosystem infrastructure.

**Executable phase status:**
- Phase 205 complete: trust-network scope lock and sponsor boundary freeze
- Phase 206 complete: trust-anchor, witness, and publication continuity
  contract
- Phase 207 complete: shared proof-profile interoperability and reviewer
  distribution path
- Phase 208 complete: trust-network rollout plan, operating model, and
  expansion decision

### v2.48 MERCURY Embedded OEM Distribution, Partner Packaging, and Bounded SDK Surface

**Goal:** Deliver one bounded embedded OEM distribution lane over the existing
MERCURY proof, inquiry, publication, supervised-live, downstream, governance,
and assurance artifacts, covering one embedded packaging profile, one partner
packaging surface, and one explicit operating boundary without turning MERCURY
into a generic SDK platform or multi-partner OEM program.

**Executable phase status:**
- Phase 201 complete: embedded OEM scope lock and partner boundary freeze
- Phase 202 complete: embedded packaging profile and OEM contract
- Phase 203 complete: partner packaging surface and embedded distribution path
- Phase 204 complete: OEM validation, operating model, and expansion decision

### v2.47 MERCURY Assurance Suite Reviewer Packages, Investigation Packaging, and External Review Readiness

**Goal:** Deliver one bounded assurance-suite lane over the existing MERCURY
proof, inquiry, publication, supervised-live, downstream, and governance
artifacts, covering internal, auditor, and counterparty reviewer packages plus
investigation-ready export surfaces without turning MERCURY into a generic
review portal or OEM platform.

**Executable phase status:**
- Phase 197 complete: assurance suite scope lock and reviewer population
  freeze
- Phase 198 complete: assurance package family and disclosure profile
  contracts
- Phase 199 complete: reviewer export surfaces and investigation packaging
- Phase 200 complete: assurance validation, reviewer operations, and expansion
  decision

### v2.46 MERCURY Governance Workbench Approval, Release, and Exception Controls

**Goal:** Deliver one bounded governance-workbench workflow over the existing
MERCURY proof, inquiry, publication, and supervised-live artifacts, covering
governed change review plus release, rollback, approval, and exception
controls without turning MERCURY into a generic workflow engine.

**Executable phase status:**
- Phase 193 complete: governance workbench scope lock and control-team
  contract freeze
- Phase 194 complete: change-review evidence model and governance decision
  package
- Phase 195 complete: release, rollback, approval, and exception workflow
  controls
- Phase 196 complete: governance validation, operations, and expansion
  decision

### v2.45 MERCURY Downstream Review Distribution and Assurance Packaging

**Goal:** Deliver one downstream archive/review/case-management distribution
path and one reviewer-assurance package family over the existing MERCURY
proof, inquiry, and supervised-live reviewer artifacts without widening into
OEM packaging, generic connector sprawl, or deep runtime coupling.

**Executable phase status:**
- Phase 189 complete: downstream review scope lock and consumer contract freeze
- Phase 190 complete: downstream distribution package and delivery contract
- Phase 191 complete: review-system connector and assurance export path
- Phase 192 complete: downstream validation, operations, and expansion
  decision

### v2.44 MERCURY Supervised-Live Bridge and Controlled Productionization

**Goal:** Move the same controlled release, rollback, and inquiry workflow
from replay/shadow into supervised-live operation while existing customer
execution systems remain primary and Chio stays the generic substrate.

**Executable phase status:**
- Phase 185 complete: supervised-live scope lock, entry criteria, and
  operating envelope
- Phase 186 complete: live/mirrored workflow intake and proof continuity
- Phase 187 complete: approval gates, interrupts, and degraded-mode operations
- Phase 188 complete: supervised-live qualification, conversion package, and
  bridge closure

### v2.43 MERCURY Evidence Productization Foundation

**Goal:** Package Chio's signed-evidence substrate into MERCURY, the first
finance-specific review-grade evidence platform for governed AI trading
workflows, starting with controlled release, rollback, and inquiry handling.

**Executable phase status:**
- Phase 181 complete: MERCURY scope lock, Chio reuse map, and workflow freeze
- Phase 182 complete: MERCURY core evidence model, metadata, and query
  indexing
- Phase 183 complete: `Proof Package v1`, `Inquiry Package v1`, and verifier
  path
- Phase 184 complete: replay/shadow pilot harness and design-partner readiness
- Phase 184.1 complete: Mercury app boundary extraction from `chio-cli`

### v2.21 Standards-Native Authorization and Credential Fabric

**Goal:** Align portable credential profiles, subject or issuer binding,
request-time authorization details, and live metadata or status surfaces into
one bounded standards-native fabric.

**Executable phase status:**
- Phase 93 complete: portable claim catalog and governed auth binding
- Phase 94 complete: multi-format credential profiles and verification
- Phase 95 complete: hosted request-time authorization and resource convergence
- Phase 96 complete: portable status, revocation, metadata, and live discovery
  alignment

### v2.22 Wallet Exchange, Identity Assertions, and Sender-Constrained Authorization

**Goal:** Add a transport-neutral wallet exchange model, optional identity
assertions, and live sender-constrained semantics over DPoP, mTLS, and one
explicitly bounded attestation-bound profile.

**Executable phase status:**
- Phase 97 complete: wallet exchange descriptor and transport-neutral
  transaction state
- Phase 98 complete: optional identity assertion and session continuity lane
- Phase 99 complete: DPoP, mTLS, and attestation-bound sender-constrained
  authorization
- Phase 100 complete: end-to-end wallet and sender-constrained qualification

### v2.23 Common Appraisal Vocabulary and External Result Interop

**Goal:** Externalize Chio's appraisal semantics into a versioned contract with
normalized claims, reason taxonomy, and signed result import or export without
widening trust from raw foreign evidence.

**Executable phase status:**
- Phase 101 complete: common appraisal schema split and artifact inventory
- Phase 102 complete: normalized claim vocabulary and reason taxonomy
- Phase 103 complete: external signed appraisal result import/export and policy
  mapping
- Phase 104 complete: mixed-provider appraisal qualification and boundary rewrite

### v2.24 Verifier Federation, Cross-Issuer Portability, and Discovery

**Goal:** Add cross-issuer trust packs, verifier descriptors, trust bundles,
public issuer or verifier discovery, and assurance-aware downstream policy
without creating ambient federation trust.

**Executable phase status:**
- Phase 105 complete: cross-issuer portfolios, trust packs, and migration
  semantics
- Phase 106 complete: verifier descriptors, trust bundles, and reference-value
  distribution
- Phase 107 complete: public issuer/verifier discovery, transparency, and
  local policy import guardrails
- Phase 108 complete: wider provider support and assurance-aware auth/economic
  policy

### v2.25 Live Capital Allocation and Escrow Execution

**Goal:** Convert bounded facility and bond policy into live capital books,
escrow or reserve instructions, governed-action allocation, and regulated-role
baseline profiles.

**Executable phase status:**
- Phase 109 complete: capital book and source-of-funds ledger
- Phase 110 complete: escrow and reserve instruction contract
- Phase 111 complete: live allocation engine for governed actions
- Phase 112 complete: capital execution qualification and regulated-role baseline

### v2.26 Reserve Control, Autonomous Pricing, and Claims Payment

**Goal:** Turn reserve posture into executable impairment, release, and slash
control, then add delegated pricing authority, automatic binding, claims
payment, and recovery clearing.

**Executable phase status:**
- Phase 113 complete: executable reserve impairment, release, and slash controls
- Phase 114 complete: delegated pricing authority and automatic coverage binding
- Phase 115 complete: automatic claims payment and payout reconciliation
- Phase 116 complete: recovery clearing, reinsurance/facility settlement, and
  role topology

### v2.27 Open Registry, Trust Activation, and Governance Network

**Goal:** Generalize Chio's curated public discovery surfaces into a generic
open registry with trust activation, open admission classes, governance
charters, and dispute escalation.

**Executable phase status:**
- Phase 117 complete: generic listing artifact and namespace model
- Phase 118 complete: origin, mirror, indexer, search, ranking, and freshness
  semantics
- Phase 119 complete: trust activation artifacts and open admission classes
- Phase 120 complete: governance charters, dispute escalation, sanctions, and
  appeals

### v2.28 Portable Reputation, Marketplace Economics, and Endgame Qualification

**Goal:** Close the full research endgame with portable reputation, fee or
bond economics, abuse resistance, adversarial multi-operator qualification, and
the final public boundary rewrite.

**Executable phase status:**
- Phase 121 complete: portable reputation, negative-event exchange, and
  weighting profiles
- Phase 122 complete: fee schedules, bonds, slashing, and abuse resistance
- Phase 123 complete: adversarial multi-operator open-market qualification
- Phase 124 complete: partner proof, release boundary, and honest endgame
  claim closure

### v2.29 Official Stack and Extension SDK

**Goal:** Freeze Chio's extension boundary so the project can ship one official
stack while allowing custom rails, anchors, oracles, identity providers,
stores, wallets, registries, and pricing engines to plug in under Chio-owned
contracts.

**Executable phase status:**
- Phase 125 complete: extension-point inventory and canonical boundary classes
- Phase 126 complete: extension manifests, negotiation, and official stack
  packaging
- Phase 127 complete: trust-preserving adapter runtime and policy enforcement
- Phase 128 complete: extension qualification, compatibility matrix, and
  boundary closure

### v2.30 Web3 Settlement Rail Dispatch and External Capital Execution

**Goal:** Build the first real web3/live-money execution stack on top of the
official extension substrate, moving Chio from custody-neutral and
settlement-neutral instruction artifacts into real external rail execution with
cryptographically reconcilable dispatch, payout, reserve, and recovery proofs.

**Executable phase status:**
- Phase 129 complete: web3 trust-boundary, identity-binding, and protocol
  freeze
- Phase 130 complete: unified contracts, bindings, and chain configuration
- Phase 131 complete: receipt-root anchoring and oracle-evidence substrate
- Phase 132 complete: escrow, bond vault, settlement dispatch, and web3
  qualification

### v2.31 Autonomous Pricing, Capital Pools, and Insurance Automation

**Goal:** Expand Chio from delegated pricing and bounded bind logic into
bounded autonomous pricing, reserve optimization, and insurer-grade capital
automation with explicit rollback and audit controls.

**Executable phase status:**
- Phase 133 complete: autonomous pricing artifacts and authority envelopes
- Phase 134 complete: capital-pool optimization and simulation controls
- Phase 135 complete: automatic reprice, renew, decline, and bind orchestration
- Phase 136 complete: drift detection, rollback, and autonomous qualification

### v2.32 Federated Trust Activation, Open Admission, and Shared Reputation Network

**Goal:** Move beyond local trust activation into cross-operator trust
federation, more open admission mechanics, and shared portable-reputation
clearing while preserving explicit anti-sybil and anti-ambient-trust controls.

**Executable phase status:**
- Phase 137 complete: cross-operator federation and trust-activation exchange
- Phase 138 complete: mirror/indexer quorum, conflict, and anti-eclipse
  semantics
- Phase 139 complete: open-admission stake classes and shared-reputation
  clearing
- Phase 140 complete: federation qualification, abuse resistance, and
  governance closure

### v2.33 Public Identity/Wallet Network and Maximal Endgame Qualification

**Goal:** Broaden Chio from bounded portable identity and wallet interop into a
multi-network public identity and wallet fabric, then close the strongest
possible reading of the research thesis with one final qualification package.

**Executable phase status:**
- Phase 141 complete: broader DID/VC method support and identity profiles
- Phase 142 complete: public wallet directory, routing, and discovery
  semantics
- Phase 143 complete: multi-wallet, multi-issuer, and cross-operator interop
  qualification
- Phase 144 complete: final maximal-endgame partner proof and boundary closure

### v2.34 Official Web3 Runtime Contracts and Deployment Harness

**Goal:** Convert Chio's frozen official web3 package into compilable
contracts, reproducible deployments, and generated bindings that runtime
services can actually target.

**Executable phase status:**
- Phase 145 complete: Solidity contract package and canonical event semantics
- Phase 146 complete: Foundry/Alloy bindings, deployment manifests, and local
  devnet harness
- Phase 147 complete: DID/key binding, verifier discovery, and contract-to-
  artifact parity
- Phase 148 complete: gas, storage, security qualification, and contract
  package release

### v2.35 chio-link Oracle Runtime and Cross-Currency Budget Enforcement

**Goal:** Productize the `chio-link` research into a real oracle runtime that
enforces cross-currency budgets with explicit provenance, staleness controls,
and fail-closed fallback behavior.

**Executable phase status:**
- Phase 149 complete: Chainlink/Pyth oracle adapters, cache, TWAP, and
  divergence policy
- Phase 150 complete: oracle evidence artifacts, kernel budget enforcement,
  and receipt integration
- Phase 151 complete: Base/Arbitrum operator configuration, monitoring, and
  circuit-breaker controls
- Phase 152 complete: `chio-link` qualification, failure drills, and boundary
  documentation

### v2.36 chio-anchor Multi-Chain Anchoring and Proof Verification

**Goal:** Productize `chio-anchor` as a real publication and verification
service over Base/Arbitrum, Bitcoin OpenTimestamps, and Solana-normalized
proof bundles.

**Executable phase status:**
- Phase 153 complete: Base/Arbitrum root publication service and inclusion proof
  verifier
- Phase 154 complete: Bitcoin OpenTimestamps secondary anchoring and
  verification
- Phase 155 complete: Solana anchor publication, proof normalization, and
  shared proof bundle
- Phase 156 complete: `chio-anchor` discovery, operations, compliance notes, and
  multi-chain qualification

### v2.37 chio-settle On-Chain Settlement, Escrow, and Bond Runtime

**Goal:** Realize `chio-settle` as a Rust execution engine that turns approved
Chio capital instructions into real on-chain escrow, release, refund, and bond
state transitions.

**Executable phase status:**
- Phase 157 complete: settlement dispatch builder and escrow/bond transaction
  orchestration
- Phase 158 complete: settlement observer, dispute windows, refunds,
  reversals, and bond lifecycle
- Phase 159 complete: Solana settlement path, Ed25519-native verification, and
  multi-chain consistency
- Phase 160 complete: `chio-settle` qualification, custody boundary, and
  regulated-role runbooks

### v2.38 Web3 Automation, Cross-Chain Transport, and Agent Payment Interop

**Goal:** Consume the parked future tracks from the research set without
smuggling them in as hidden backlog: Chainlink Functions, Automation, CCIP,
x402, Circle nanopayments, and ERC-4337/paymaster compatibility.

**Executable phase status:**
- Phase 161 complete: Chainlink Functions proof verification and EVM Ed25519
  fallback strategy
- Phase 162 complete: Chainlink Automation for anchoring, settlement
  watchdogs, and bond jobs
- Phase 163 complete: CCIP delegation/settlement transport and cross-chain
  receipt reconciliation
- Phase 164 complete: x402 surface, Circle nanopayments, and ERC-4337
  paymaster compatibility

### v2.39 Web3 Production Qualification, Operations, and Public Claim Closure

**Goal:** Turn the new web3 runtime stack into something Chio can operate,
qualify, and describe publicly without hiding residual risks.

**Executable phase status:**
- Phase 165 complete: observability, indexers, reorg recovery, and
  pause/emergency controls
- Phase 166 complete: security audit remediation, gas/latency budgets, and
  deployment promotion
- Phase 167 complete: external testnet/mainnet partner proof and full-ladder
  qualification
- Phase 168 complete: final protocol/release boundary rewrite and post-research
  claim closure

### v2.40 Web3 Runtime Integrity, Evidence Gating, and Contract Coherence

**Goal:** Make Chio's bounded web3 runtime concurrency-safe, evidence-
mandatory, and internally consistent across kernel, runtime, bindings, and
contracts.

**Executable phase status:**
- Phase 169 complete: deterministic settlement identity, duplicate-replay
  guards, and receipt reconciliation across escrow and bond dispatch
- Phase 170 complete: mandatory receipt storage, checkpointing, and web3
  evidence gates
- Phase 171 complete: collateral-versus-reserve-requirement truth and
  canonical `chio-link` oracle authority across contracts, config, evidence,
  and docs
- Phase 172 complete: cryptographic secondary-lane verification,
  artifact-derived bindings, and contract/runtime parity qualification

### v2.41 Hosted Qualification, Deployment Promotion, and Operator Controls

**Goal:** Turn Chio's bounded web3-runtime stack from a locally qualified
surface into one with hosted proof, reproducible promotion, and exercised
operator controls.

**Executable phase status:**
- Phase 173 complete: hosted web3 qualification workflow, staged artifact
  publication, and hosted gate wiring
- Phase 174 complete: live deployment runner, promotion approvals, and
  reproducible rollout
- Phase 175 complete: generated runtime reports, persisted control-state
  traces, and exercisable emergency controls
- Phase 176 complete: integrated recovery, dual-sign settlement, and
  partner-ready end-to-end qualification

### v2.42 Release Truth, Planning Integrity, and Assurance Backfill

**Goal:** Make Chio's release governance, authoritative docs, planning
tooling, and late-phase assurance artifacts as trustworthy as the runtime
stack they describe.

**Executable phase status:**
- Phase 177 complete: release governance, audit truth, and candidate
  documentation alignment
- Phase 178 complete: protocol/standards parity, research supersession, and
  residual gap clarity
- Phase 179 complete: GSD health, roadmap parsing, and assurance artifact
  backfill
- Phase 180 complete: runtime boundary decomposition, ownership hardening, and
  source-shape regression coverage

## Previous Milestones

### v2.8 Risk, Attestation, and Launch Closure

**Goal:** Turn Chio's evidence substrate into an externally defensible launch
package with risk export, runtime assurance, and final qualification proof.

**Completed features:**
- signed insurer-facing behavioral feed and export tooling
- runtime-assurance-aware issuance, approvals, and budget constraints
- explicit executable proof/spec/runtime closure boundary
- launch audit, partner proof, and local technical-go decision package

### v2.9 Economic Evidence and Authorization Context Interop

**Goal:** Standardize truthful cost evidence and external authorization
context so Chio's governed approvals and receipts can participate cleanly in
IAM, billing, and partner ecosystems.

**Completed features:**
- generic metered billing evidence contracts now exist for non-rail tools
- post-execution cost evidence can be reconciled without mutating signed
  receipt truth
- governed receipts now project into authorization-details style context plus
  delegated call-chain provenance
- economic interop now has focused operator, qualification, and partner-proof
  documentation

### v2.7 Portable Trust, Certification, and Federation Maturity

**Goal:** Make portable identity, passport lifecycle, certification discovery,
and cross-org trust exchange truthful enough to support later underwriting and
interop layers.

**Completed features:**
- enterprise identity provenance is explicit in portable trust artifacts
- passport lifecycle, distribution, revocation, and supersession are
  first-class
- certification discovery works across operator surfaces with truthful
  revocation and provenance
- imported reputation remains attenuated, evidence-backed, and policy-visible

### v2.6 Governed Transactions and Payment Rails

**Goal:** Make governed intent, approval evidence, and truthful commercial
bridges first-class runtime behavior rather than loose documentation claims.

**Completed features:**
- governed transaction intents and approval evidence are typed policy and
  receipt inputs
- truthful x402 prepaid API flows and ACP/shared-payment-token seller-scoped
  commerce approvals are implemented
- settlement reconciliation, backlog reporting, and multi-dimensional budget
  reporting exist without mutating signed receipt truth

### v2.5 Chio Rename and Identity Realignment

**Goal:** Rename the project and product from PACT to Chio across code,
packages, CLI, docs, spec, and portable-trust surfaces without losing
compatibility, verifiability, or operator clarity.

**Completed features:**
- Chio became the primary Cargo package, CLI, SDK, release, and maintained
  documentation identity
- Chio-primary schema issuance now ships where the rename contract called for
  it, while `did:chio` and the documented compatibility freezes remain intact
- Chio-first docs, migration guides, release candidate materials, and final
  qualification evidence align to one product narrative

## Historical Milestone Snapshot: v2.10 Underwriting and Risk Decisioning

**Goal:** Convert Chio from a truthful risk-evidence exporter into a bounded
runtime underwriting and risk-decisioning system.

**Why now:**
- `docs/research/DEEP_RESEARCH_1.md` places underwriting after standardized
  cost semantics and transaction context.
- `spec/PROTOCOL.md` still explicitly says Chio exports truthful risk evidence
  rather than underwriting decisions.
- `docs/ECONOMIC_INTEROP_GUIDE.md` now documents the interop layer that later
  underwriting work will consume.

**Target features:**
- signed underwriting-policy inputs and canonical risk taxonomy
- runtime decisions that approve, deny, step-up, or reduce ceilings
- separate signed underwriting artifacts for budgets, premiums, and appeals
- operator simulation, explanation, and qualification evidence

**Executable phase sequence:**
- Phase 49: Underwriting Taxonomy and Policy Inputs
- Phase 50: Runtime Underwriting Decision Engine
- Phase 51: Signed Risk Decisions, Budget/Premium Outputs, and Appeals
- Phase 52: Underwriting Simulation, Qualification, and Partner Proof

**Current phase status:**
- Phase 49 complete: signed underwriting-input contract, trust-control report
  surface, CLI export path, and fail-closed validation are shipped
- Phase 50 complete: deterministic runtime underwriting evaluator and
  explanation surfaces are shipped
- Phase 51 complete: signed underwriting decisions, lifecycle projection,
  premium outputs, and appeal handling are shipped
- Phase 52 complete: operator simulation, qualification, partner proof, and
  milestone audit closure are shipped

## Historical Milestone Snapshot: v2.12 Workload Identity and Attestation Verification Bridges

**Goal:** Bind Chio's runtime-assurance model to concrete workload identity and
attestation verifier systems rather than only normalized upstream evidence.

**Research and boundary references:**
- `docs/research/DEEP_RESEARCH_1.md` on SPIFFE/SVID, workload identity, and
  attestation-backed runtime trust
- `crates/chio-core/src/capability.rs` on normalized runtime-attestation and
  workload-identity types
- `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md` and `spec/PROTOCOL.md` on
  conservative verifier and workload-identity boundaries

**Target features:**
- typed SPIFFE/SVID-style workload identity mapping
- one concrete Azure Attestation verifier bridge
- explicit trusted-verifier rebinding into runtime-assurance policy
- qualification and operator runbooks for verifier failure and recovery

**Executable phase sequence:**
- Phase 57: SPIFFE/SVID Workload Identity Mapping
- Phase 58: Cloud Attestation Verifier Adapters
- Phase 59: Attestation Trust Policy and Runtime-Assurance Rebinding
- Phase 60: Workload Identity Qualification and Operator Runbooks

**Current phase status:**
- Phase 57 complete: SPIFFE/SVID-style workload identity is now typed,
  fail-closed, and bound into issuance, governed receipts, and policy-visible
  attestation context
- Phase 58 complete: Azure Attestation JWTs now normalize into Chio
  runtime-attestation evidence through an explicit conservative verifier bridge
- Phase 59 complete: trusted-verifier policy now rebinds attested evidence into
  effective runtime-assurance tiers and denies stale or unmatched evidence fail
  closed
- Phase 60 complete: qualification, runbook, release-audit, and partner-proof
  materials now close the verifier boundary locally

## Historical Milestone Snapshot: v2.11 Portable Credential Interop and Wallet Distribution

**Goal:** Expand Chio's portable trust into external VC, wallet, and verifier
ecosystems without inventing synthetic global trust.

**Research and boundary references:**
- `docs/research/DEEP_RESEARCH_1.md` on OID4VCI and wallet-mediated passport
  portability
- `crates/chio-credentials/src/lib.rs` on the current intentionally simple
  Chio-native credential format
- `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md` and `spec/PROTOCOL.md` on
  current conservative portability boundaries

**Target features:**
- interoperable credential issuance and delivery
- portable status, revocation, and distribution semantics
- holder-facing wallet and presentation transport contracts
- external verifier compatibility qualification

## Requirements

### Validated

- Capability-scoped mediation, guard evaluation, signed receipts, and release
  qualification -- v1.0
- Agent economy foundation: monetary budgets, checkpoints, receipts, evidence
  export, reputation, passports, A2A alpha, and early federation -- v2.0
- Enterprise federation admin, multi-issuer passport composition, verifier
  policy artifacts, and shared remote evidence analytics -- v2.1
- A2A partner hardening, durable task correlation, and registry-backed
  certification publication/resolution/revocation -- v2.2
- Release hygiene, observability, protocol v2 alignment, and launch-readiness
  evidence -- v2.3
- Runtime, service, storage, and adapter decomposition with layering guardrails
  -- v2.4
- Chio rename and identity realignment across packages, schemas, CLI, and docs
  -- v2.5
- Governed transaction intent, truthful payment-rail bridges, reconciliation,
  and multi-dimensional budgets -- v2.6
- Enterprise identity provenance, passport lifecycle, certification discovery,
  and conservative imported trust -- v2.7
- Signed behavioral feed export, runtime assurance tiers, formal/spec/runtime
  closure, and launch package artifacts -- v2.8

### Earlier Completed

- [x] **EEI-01**: Generic quote, cap, and post-execution cost evidence for
  non-payment-rail tools
- [x] **EEI-02**: Pluggable metered-cost evidence adapters with truthful
  reconciliation
- [x] **EEI-03**: Governed approvals and receipts map into external
  authorization context
- [x] **EEI-04**: Delegated call-chain context is explicit without widening
  identity or billing scope
- [x] **EEI-05**: Operator tooling and qualification make Chio's economic
  interop legible to finance, IAM, and partners

### Historical Snapshot

- [x] **ATTEST-01**: Workload identity maps explicitly into Chio runtime and
  policy decisions
- [x] **ATTEST-02**: At least one concrete attestation verifier bridge ships
- [x] **ATTEST-03**: Attestation trust policy is explicit and fail-closed
- [x] **ATTEST-04**: Verified evidence can narrow or widen rights only
  through explicit policy
- [x] **ATTEST-05**: Qualification and runbooks cover verifier failure and
  replay semantics

### Out of Scope

- Chio as a direct payment rail -- Chio bridges to rails and meters them
  truthfully; it does not become a settlement network itself
- Synthetic global trust score -- imported trust remains evidence-backed,
  attenuated, and operator-bounded
- Public mutable certification marketplace -- discovery remains conservative
  until an explicit future milestone widens it
- Automatic enterprise identity propagation that widens authority -- identity
  context must never silently expand trust, rights, or billing scope
- External release publication from local evidence alone -- hosted workflow
  observation remains a required pre-publication gate

## Context

Chio is now the primary product, CLI, SDK, release, and documentation identity.
`v2.5` through `v2.8` closed the rename, governed-economics, portable-trust,
and launch-readiness waves derived from `docs/research/DEEP_RESEARCH_1.md`.
The later maximal-endgame ladder is now also complete locally through
extension packaging, official web3 settlement, bounded autonomous pricing,
federated trust activation, and the bounded public identity-network surface.

Current doc boundaries are explicit about what still remains intentionally out
of scope:
- `spec/PROTOCOL.md` keeps `did:chio` as the provenance anchor even where the
  public identity profile names bounded `did:web`, `did:key`, or `did:jwk`
  compatibility inputs.
- `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md` excludes permissionless
  public wallet routing, universal trust scoring, and ambient-trust discovery
  semantics.
- `docs/release/RELEASE_CANDIDATE.md` and `docs/release/PARTNER_PROOF.md`
  keep hosted workflow observation as a required publication gate beyond local
  technical completion.

Key regulatory milestones achieved:
- Colorado SB 24-205 compliance document filed (deadline June 30, 2026)
- EU AI Act Article 19 compliance document filed (deadline August 2, 2026)

## Constraints

- **Tech stack**: Rust 2021 workspace, Rust 1.93 MSRV.
- **Compatibility**: v1.0 through v2.8 behavior must remain truthful unless
  intentionally versioned and documented.
- **Security**: Fail-closed behavior remains mandatory. New interop work cannot
  silently widen trust, identity, or billing authority.
- **Operational quality**: `cargo fmt`, `cargo clippy`, and
  `cargo test --workspace` remain hard gates, not advisory checks.
- **Execution system**: `.planning/` remains the active source of truth for
  milestone and phase execution.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Chio stays separate from ClawdStrike | Protocol must be vendor-neutral for standards submissions | Maintained |
| Single currency first for monetary budgets | Multi-currency adds exchange-rate complexity | Shipped v2.0 |
| Port ClawdStrike code rather than rewrite | Production-tested code adapted faster | DPoP, velocity, SIEM ported |
| `chio-siem` as separate crate with no kernel dependency | Kernel TCB isolation requirement | Verified |
| v2.3 started with hygiene and productionization | Feature breadth was ahead of release readiness and maintainability | Completed |
| v2.4 focused on architecture instead of more breadth | Ownership radius and maintainability were the next risk | Completed |
| Chio rename came before the next feature wave | Product identity, package names, docs, and standards story needed to be coherent before adding more external integrations | Completed in v2.5 |
| Rename stayed compatibility-led instead of a blind search/replace | Signed artifacts, CLI workflows, SDK imports, and portable-trust identities already existed | Completed in v2.5 |
| Governed transactions and payment rails were the first post-rename feature wave | They made the economic-security thesis concrete with the fastest external resonance | Completed in v2.6 |
| Portable trust and certification maturity followed the rail bridges | Discovery, status, and cross-org trust semantics depended on a clearer product identity and stable commercial story | Completed in v2.7 |
| Insurer feeds, attestation tiers, and GA closure followed evidence and portability maturity | Underwriting and launch claims depended on earlier substrate stability | Completed in v2.8 |
| Economic evidence and authorization context interop comes before underwriting | `docs/research/DEEP_RESEARCH_1.md` makes standardized cost semantics and transaction context prerequisites for runtime decisioning | Completed in v2.9 |
| Runtime underwriting comes before wallet and verifier expansion | Chio should first define its own signed risk-decision semantics before exporting them into broader credential ecosystems | Completed in v2.10 |
| Broader credential interop must preserve Chio's conservative trust boundaries | External portability is valuable only if it does not invent global trust, silent federation, or synthetic scoring | Completed in v2.11 |
| Workload identity bridges follow portable and economic interop | Concrete verifier integrations should bind into already-stabilized policy, credential, and economic semantics | Completed in v2.12 |

---
*Last updated: 2026-04-19 after completing the post-v3.18 closure tracker and final release-truth sync gate*
