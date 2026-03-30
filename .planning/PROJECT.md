# ARC

## What This Is

ARC (Attested Rights Channel) is the protocol and trust-control plane for
deterministic, attested agent access to tools, resources, and cross-agent
workflows. The shipped codebase is now ARC-first, with only a small number of
explicitly deprecated Pact-era compatibility shims retained where transition
safety still matters. ARC combines capability-based security, cryptographic
receipts, governed economics, portable trust, and cross-org evidence exchange
so operators can prove what an agent was allowed to do, what it actually did,
and how that activity should be trusted across boundaries.

## Core Value

ARC must provide deterministic, least-privilege agent authority with auditable
outcomes, bounded spend, and cryptographic proof artifacts that enable economic
security, regulatory compliance, and portable trust.

## Current State

**Latest completed milestone:** v2.22 Wallet Exchange, Identity Assertions, and
Sender-Constrained Authorization (completed locally 2026-03-30)
**Archive:** `.planning/milestones/v2.22-MILESTONE-AUDIT.md`
**Audit:** `.planning/v2.22-MILESTONE-AUDIT.md`
**Active milestone:** v2.23 Common Appraisal Vocabulary and External Result
Interop
**Next milestone after active:** v2.24 Verifier Federation, Cross-Issuer
Portability, and Discovery

`v2.5` through `v2.8` executed the rename, governed-economics, portable-trust,
and launch-closure ladder derived from `docs/research/DEEP_RESEARCH_1.md`.
ARC now sits at a locally qualified launch package with hosted workflow
observation still required before external publication, plus completed
economic-interop, underwriting, portable credential, verifier-side OID4VP,
multi-cloud attestation, and enterprise-IAM profile layers. ARC now ships a
normative authorization profile, sender-constrained discovery semantics,
machine-readable profile metadata, reviewer packs tied back to signed receipt
truth, fail-closed qualification over malformed sender, assurance, and
delegated-call-chain projection, plus a governed public certification
marketplace surface with versioned evidence profiles, public metadata,
search/transparency, and dispute-aware consumption semantics. ARC now also
ships signed exposure, scorecard, facility, credit-backtest,
provider-risk-package, reserve-state bond artifacts, immutable bond-loss
lifecycle state, and one bonded-execution simulation lane with explicit
operator control policy from `v2.18` and `v2.19`. ARC now also ships one
curated liability-provider registry with signed provider-policy artifacts and
fail-closed jurisdiction or coverage resolution, plus canonical quote-request,
quote-response, placement, and bound-coverage artifacts over one signed risk
package, plus immutable claim-package, provider-response, dispute, and
adjudication artifacts, with `v2.20` now closing the liability-market ladder
locally through marketplace qualification and partner-proof boundary updates.
The remaining work is no longer "core ARC." It is the post-`v2.20` endgame
ladder that turns ARC from a bounded research-complete control plane into a
full standards-native, assurance-federated, live-capital, and open-market
infrastructure surface. That ladder is now normalized in
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md`.

## Planned Roadmap

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

**Goal:** Externalize ARC's appraisal semantics into a versioned contract with
normalized claims, reason taxonomy, and signed result import or export without
widening trust from raw foreign evidence.

**Executable phase status:**
- Phase 101 ready: common appraisal schema split and artifact inventory
- Phase 102 ready: normalized claim vocabulary and reason taxonomy
- Phase 103 ready: external signed appraisal result import/export and policy
  mapping
- Phase 104 ready: mixed-provider appraisal qualification and boundary rewrite

### v2.24 Verifier Federation, Cross-Issuer Portability, and Discovery

**Goal:** Add cross-issuer trust packs, verifier descriptors, trust bundles,
public issuer or verifier discovery, and assurance-aware downstream policy
without creating ambient federation trust.

**Executable phase status:**
- Phase 105 ready: cross-issuer portfolios, trust packs, and migration
  semantics
- Phase 106 ready: verifier descriptors, trust bundles, and reference-value
  distribution
- Phase 107 ready: public issuer/verifier discovery, transparency, and local
  policy import guardrails
- Phase 108 ready: wider provider support and assurance-aware auth/economic
  policy

### v2.25 Live Capital Allocation and Escrow Execution

**Goal:** Convert bounded facility and bond policy into live capital books,
escrow or reserve instructions, governed-action allocation, and regulated-role
baseline profiles.

**Executable phase status:**
- Phase 109 ready: capital book and source-of-funds ledger
- Phase 110 ready: escrow and reserve instruction contract
- Phase 111 ready: live allocation engine for governed actions
- Phase 112 ready: capital execution qualification and regulated-role baseline

### v2.26 Reserve Control, Autonomous Pricing, and Claims Payment

**Goal:** Turn reserve posture into executable impairment, release, and slash
control, then add delegated pricing authority, automatic binding, claims
payment, and recovery clearing.

**Executable phase status:**
- Phase 113 ready: executable reserve impairment, release, and slash controls
- Phase 114 ready: delegated pricing authority and automatic coverage binding
- Phase 115 ready: automatic claims payment and payout reconciliation
- Phase 116 ready: recovery clearing, reinsurance/facility settlement, and
  role topology

### v2.27 Open Registry, Trust Activation, and Governance Network

**Goal:** Generalize ARC's curated public discovery surfaces into a generic
open registry with trust activation, open admission classes, governance
charters, and dispute escalation.

**Executable phase status:**
- Phase 117 ready: generic listing artifact and namespace model
- Phase 118 ready: origin, mirror, indexer, search, ranking, and freshness
  semantics
- Phase 119 ready: trust activation artifacts and open admission classes
- Phase 120 ready: governance charters, dispute escalation, sanctions, and
  appeals

### v2.28 Portable Reputation, Marketplace Economics, and Endgame Qualification

**Goal:** Close the full research endgame with portable reputation, fee or
bond economics, abuse resistance, adversarial multi-operator qualification, and
the final public boundary rewrite.

**Executable phase status:**
- Phase 121 ready: portable reputation, negative-event exchange, and weighting
  profiles
- Phase 122 ready: fee schedules, bonds, slashing, and abuse resistance
- Phase 123 ready: adversarial multi-operator open-market qualification
- Phase 124 ready: partner proof, release boundary, and honest endgame claim
  closure

## Previous Milestones

### v2.8 Risk, Attestation, and Launch Closure

**Goal:** Turn ARC's evidence substrate into an externally defensible launch
package with risk export, runtime assurance, and final qualification proof.

**Completed features:**
- signed insurer-facing behavioral feed and export tooling
- runtime-assurance-aware issuance, approvals, and budget constraints
- explicit executable proof/spec/runtime closure boundary
- launch audit, partner proof, and local technical-go decision package

### v2.9 Economic Evidence and Authorization Context Interop

**Goal:** Standardize truthful cost evidence and external authorization
context so ARC's governed approvals and receipts can participate cleanly in
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

### v2.5 ARC Rename and Identity Realignment

**Goal:** Rename the project and product from PACT to ARC across code,
packages, CLI, docs, spec, and portable-trust surfaces without losing
compatibility, verifiability, or operator clarity.

**Completed features:**
- ARC became the primary Cargo package, CLI, SDK, release, and maintained
  documentation identity
- ARC-primary schema issuance now ships where the rename contract called for
  it, while `did:arc` and the documented compatibility freezes remain intact
- ARC-first docs, migration guides, release candidate materials, and final
  qualification evidence align to one product narrative

## Historical Milestone Snapshot: v2.10 Underwriting and Risk Decisioning

**Goal:** Convert ARC from a truthful risk-evidence exporter into a bounded
runtime underwriting and risk-decisioning system.

**Why now:**
- `docs/research/DEEP_RESEARCH_1.md` places underwriting after standardized
  cost semantics and transaction context.
- `spec/PROTOCOL.md` still explicitly says ARC exports truthful risk evidence
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

**Goal:** Bind ARC's runtime-assurance model to concrete workload identity and
attestation verifier systems rather than only normalized upstream evidence.

**Research and boundary references:**
- `docs/research/DEEP_RESEARCH_1.md` on SPIFFE/SVID, workload identity, and
  attestation-backed runtime trust
- `crates/arc-core/src/capability.rs` on normalized runtime-attestation and
  workload-identity types
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` and `spec/PROTOCOL.md` on
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
- Phase 58 complete: Azure Attestation JWTs now normalize into ARC
  runtime-attestation evidence through an explicit conservative verifier bridge
- Phase 59 complete: trusted-verifier policy now rebinds attested evidence into
  effective runtime-assurance tiers and denies stale or unmatched evidence fail
  closed
- Phase 60 complete: qualification, runbook, release-audit, and partner-proof
  materials now close the verifier boundary locally

## Historical Milestone Snapshot: v2.11 Portable Credential Interop and Wallet Distribution

**Goal:** Expand ARC's portable trust into external VC, wallet, and verifier
ecosystems without inventing synthetic global trust.

**Research and boundary references:**
- `docs/research/DEEP_RESEARCH_1.md` on OID4VCI and wallet-mediated passport
  portability
- `crates/arc-credentials/src/lib.rs` on the current intentionally simple
  ARC-native credential format
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` and `spec/PROTOCOL.md` on
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
- ARC rename and identity realignment across packages, schemas, CLI, and docs
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
- [x] **EEI-05**: Operator tooling and qualification make ARC's economic
  interop legible to finance, IAM, and partners

### Historical Snapshot

- [x] **ATTEST-01**: Workload identity maps explicitly into ARC runtime and
  policy decisions
- [x] **ATTEST-02**: At least one concrete attestation verifier bridge ships
- [x] **ATTEST-03**: Attestation trust policy is explicit and fail-closed
- [x] **ATTEST-04**: Verified evidence can narrow or widen rights only
  through explicit policy
- [x] **ATTEST-05**: Qualification and runbooks cover verifier failure and
  replay semantics

### Out of Scope

- ARC as a direct payment rail -- ARC bridges to rails and meters them
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

ARC is now the primary product, CLI, SDK, release, and documentation identity.
`v2.5` through `v2.8` closed the rename, governed-economics, portable-trust,
and launch-readiness waves derived from `docs/research/DEEP_RESEARCH_1.md`.
What remains from that research is not the ARC core itself. It is the next
layer above the core: generic economic evidence, runtime underwriting, external
credential interop, and concrete workload-identity / attestation bridges.

Current doc boundaries are explicit about those remaining gaps:
- `spec/PROTOCOL.md` says the behavioral feed is truthful evidence export, not
  an underwriting model.
- `crates/arc-credentials/src/lib.rs` still describes the credential format as
  intentionally simple and ARC-native.
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` excludes global trust
  registry, synthetic cross-issuer scoring, and public wallet distribution
  semantics.
- `crates/arc-core/src/lib.rs` allows SPIFFE-like identifiers but currently
  treats them as opaque strings.

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
| ARC stays separate from ClawdStrike | Protocol must be vendor-neutral for standards submissions | Maintained |
| Single currency first for monetary budgets | Multi-currency adds exchange-rate complexity | Shipped v2.0 |
| Port ClawdStrike code rather than rewrite | Production-tested code adapted faster | DPoP, velocity, SIEM ported |
| `arc-siem` as separate crate with no kernel dependency | Kernel TCB isolation requirement | Verified |
| v2.3 started with hygiene and productionization | Feature breadth was ahead of release readiness and maintainability | Completed |
| v2.4 focused on architecture instead of more breadth | Ownership radius and maintainability were the next risk | Completed |
| ARC rename came before the next feature wave | Product identity, package names, docs, and standards story needed to be coherent before adding more external integrations | Completed in v2.5 |
| Rename stayed compatibility-led instead of a blind search/replace | Signed artifacts, CLI workflows, SDK imports, and portable-trust identities already existed | Completed in v2.5 |
| Governed transactions and payment rails were the first post-rename feature wave | They made the economic-security thesis concrete with the fastest external resonance | Completed in v2.6 |
| Portable trust and certification maturity followed the rail bridges | Discovery, status, and cross-org trust semantics depended on a clearer product identity and stable commercial story | Completed in v2.7 |
| Insurer feeds, attestation tiers, and GA closure followed evidence and portability maturity | Underwriting and launch claims depended on earlier substrate stability | Completed in v2.8 |
| Economic evidence and authorization context interop comes before underwriting | `docs/research/DEEP_RESEARCH_1.md` makes standardized cost semantics and transaction context prerequisites for runtime decisioning | Completed in v2.9 |
| Runtime underwriting comes before wallet and verifier expansion | ARC should first define its own signed risk-decision semantics before exporting them into broader credential ecosystems | Completed in v2.10 |
| Broader credential interop must preserve ARC's conservative trust boundaries | External portability is valuable only if it does not invent global trust, silent federation, or synthetic scoring | Completed in v2.11 |
| Workload identity bridges follow portable and economic interop | Concrete verifier integrations should bind into already-stabilized policy, credential, and economic semantics | Completed in v2.12 |

---
*Last updated: 2026-03-28 after completing v2.12 workload identity and attestation verification bridges*
