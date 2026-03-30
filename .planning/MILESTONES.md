# Milestones

## Active Milestone

### v2.23 Common Appraisal Vocabulary and External Result Interop

**Executable phases:** 101-104

**Why this milestone matters:** ARC now has concrete multi-cloud verifier
bridges, but those outputs still stop at ARC-local adapter semantics. `v2.23`
is where ARC turns appraisal into a portable external result contract with one
claim vocabulary, one reason taxonomy, and explicit import/export guardrails.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on verifier-result portability,
  standards-facing attestation semantics, and vendor-neutral appraisal layers
- `spec/PROTOCOL.md` and `docs/release/RELEASE_CANDIDATE.md` on ARC's current
  bounded appraisal contract and multi-cloud bridge boundary
- `.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` on the normalized
  post-`v2.20` endgame sequence

**Key intended outcomes:**
- one outward-facing appraisal artifact boundary
- one normalized claim and reason vocabulary shared across verifier families
- signed appraisal import/export with explicit local policy mapping
- qualification evidence honest enough to claim external appraisal interop

**Status:** active; phases `101` through `104` are executable on disk.

### v2.22 Wallet Exchange, Identity Assertions, and Sender-Constrained Authorization

**Executable phases:** 97-100

**Why this milestone matters:** ARC now has a standards-native credential and
request-time authorization fabric, but it still lacks bounded wallet exchange,
identity continuity, and live sender-constrained runtime behavior. `v2.22` is
where ARC turns those next interop claims into real replay-safe flows.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on wallet exchange, session continuity,
  and sender-constrained live authorization
- `spec/PROTOCOL.md` and `docs/release/RELEASE_CANDIDATE.md` on ARC's current
  bounded OID4VP and hosted auth boundary
- `.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` on the normalized
  post-`v2.20` endgame sequence

**Key intended outcomes:**
- transport-neutral wallet exchange descriptors and replay-safe transaction
  state
- one optional identity-assertion lane for verifier continuity
- bounded DPoP, mTLS, and attestation-bound sender semantics at runtime
- qualification evidence across same-device, cross-device, and asynchronous
  exchange paths

**Status:** complete locally 2026-03-30; phases `97` through `100` are
implemented, verified, and audited.

---

## Remaining Activated Milestones

### v2.23 Common Appraisal Vocabulary and External Result Interop

**Executable phases:** 101-104
**Goal:** Turn ARC's current appraisal bridge into a versioned external result
contract with normalized claims, reason taxonomy, and import or export
semantics that remain separated from local policy decisions.

### v2.24 Verifier Federation, Cross-Issuer Portability, and Discovery

**Executable phases ready:** 105-108
**Goal:** Add cross-issuer trust packs, verifier descriptors, trust bundles,
public issuer or verifier discovery, and assurance-aware downstream policy
without ambient trust widening.

### v2.25 Live Capital Allocation and Escrow Execution

**Executable phases ready:** 109-112
**Goal:** Convert bounded facility and bond policy into live capital books,
escrow or reserve instructions, governed-action allocation, and regulated-role
baseline profiles.

### v2.26 Reserve Control, Autonomous Pricing, and Claims Payment

**Executable phases ready:** 113-116
**Goal:** Add executable reserve control, delegated pricing authority,
automatic coverage binding, claims payment, and recovery or reinsurance
clearing under explicit role topology.

### v2.27 Open Registry, Trust Activation, and Governance Network

**Executable phases ready:** 117-120
**Goal:** Generalize ARC's curated public discovery into a generic open
registry with trust activation, open admission classes, governance charters,
and federated dispute escalation.

### v2.28 Portable Reputation, Marketplace Economics, and Endgame Qualification

**Executable phases ready:** 121-124
**Goal:** Close the full research endgame with portable reputation,
marketplace economics, abuse resistance, adversarial multi-operator
qualification, and the final partner-proof and release-boundary rewrite.

---

## Latest Completed Milestone

### v2.22 Wallet Exchange, Identity Assertions, and Sender-Constrained Authorization

**Executable phases:** 97-100

**Why this milestone matters:** ARC now has a standards-native credential and
request-time authorization fabric, but it still lacked bounded wallet
exchange, identity continuity, and live sender-constrained runtime behavior.
`v2.22` is where ARC turned those next interop claims into real replay-safe
flows.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on wallet exchange, session continuity,
  and sender-constrained live authorization
- `spec/PROTOCOL.md` and `docs/release/RELEASE_CANDIDATE.md` on ARC's current
  bounded OID4VP and hosted auth boundary
- `.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` on the normalized
  post-`v2.20` endgame sequence

**Key intended outcomes:**
- transport-neutral wallet exchange descriptors and replay-safe transaction
  state
- one optional identity-assertion lane for verifier continuity
- bounded DPoP, mTLS, and attestation-bound sender semantics at runtime
- qualification evidence across same-device, cross-device, and asynchronous
  exchange paths

**Status:** complete locally 2026-03-30; phases `97` through `100` are
implemented, verified, and audited.

---

## Previous Completed Milestone

### v2.20 Liability Marketplace and Claims Network

**Executable phases:** 89-92

**Why this milestone matters:** ARC now ships signed exposure, facility, bond,
delinquency, and bonded-execution simulation artifacts, but the full research
endgame still requires live capital execution, broader standards fabric, and a
more open trust-market network beyond the curated liability-market layer.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on insurer-like market structure, quote
  and bind flows, and liability coordination above underwriting and credit
- `spec/PROTOCOL.md` and `docs/release/RELEASE_CANDIDATE.md` on ARC's current
  stop at bounded liability orchestration rather than live capital execution
- `.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` on the normalized
  ladder after `v2.20`

**Key intended outcomes:**
- curated provider registry and jurisdiction policy
- canonical quote, placement, and bound-coverage artifacts
- immutable claim, dispute, and adjudication evidence
- qualification and partner proof strong enough to close the bounded
  liability-market ladder

**Status:** complete locally 2026-03-29; phases `89` through `92` are
complete and the milestone audit is written.

---

## Previous Completed Milestone

### v2.19 Bonded Autonomy and Facility Execution (Completed)

**Executable phases:** 85-88

**Why this milestone matters:** ARC already shipped signed credit and facility
artifacts, but the research endgame still needed those surfaces to become
runtime capital posture. `v2.19` turned facility review into reserve-backed
autonomy gates, immutable loss lifecycle state, and operator-visible bonded
execution simulation without yet claiming a provider marketplace or claims
network.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on bonded agents, reserve-backed
  autonomy, and staking-like market discipline
- `spec/PROTOCOL.md` and `docs/release/RELEASE_CANDIDATE.md` on ARC's bounded
  bonded-execution boundary
- `.planning/research/POST_V2_12_RESEARCH_COMPLETION_SYNTHESIS.md` on the
  remaining liability-market gaps after `v2.19`

**Key intended outcomes:**
- signed bond, reserve, and collateral artifacts
- runtime autonomy gates that fail closed on missing capital posture
- immutable delinquency, loss, recovery, and reserve-release state
- qualification and operator controls strong enough to support the liability
  milestone

**Status:** complete locally 2026-03-29; phases `85` through `88` are
complete and the milestone audit is written.

---

## Previous Completed Milestone

### v2.17 ARC Certify Public Discovery Marketplace and Governance (Completed)

**Executable phases:** 77-80

**Why this milestone matters:** ARC already ships signed certification
artifacts plus bounded operator discovery, but the research endgame still
needed a governed public marketplace surface with explicit provenance,
transparency, and dispute semantics. `v2.17` widened discovery without turning
listing presence into automatic runtime trust.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on certification, registry fees, and
  trust-market infrastructure
- `spec/PROTOCOL.md` and `docs/release/RELEASE_CANDIDATE.md` on ARC's current
  operator-scoped certification discovery boundary
- `.planning/research/POST_V2_12_RESEARCH_COMPLETION_SYNTHESIS.md` on the
  remaining public-marketplace gap after `v2.16`

**Key intended outcomes:**
- public certification criteria and conformance evidence profiles
- public operator identity and discovery metadata
- searchable, provenance-preserving transparency surfaces
- governed dispute semantics and marketplace qualification artifacts

**Status:** complete locally 2026-03-29; phases `77` through `80` are
complete and the milestone audit is written.

---

## Previous Completed Milestone

### v2.15 Multi-Cloud Attestation and Appraisal Contracts (Completed)

**Executable phases:** 69-72

**Why this milestone matters:** `v2.12` proved ARC can bridge workload
identity and cloud attestation into runtime trust, but the boundary remained
too Azure-shaped. `v2.15` created one canonical appraisal contract, proved ARC
can evaluate materially different verifier families, and made the
normalization boundary explicit.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on SPIFFE, RATS, EAT, and cloud
  attestation as inputs into bounded trust decisions
- `docs/WORKLOAD_IDENTITY_RUNBOOK.md` and
  `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` on the current verifier
  bridge boundary
- `.planning/research/POST_V2_12_RESEARCH_COMPLETION_SYNTHESIS.md` on the
  remaining multi-cloud appraisal gap after `v2.12`

**Key intended outcomes:**
- one canonical appraisal contract across verifier families
- concrete AWS Nitro and Google verifier adapters beside Azure
- adapter-aware runtime-assurance and underwriting semantics
- qualification and export artifacts strong enough to update the public
  attestation boundary honestly

**Status:** complete locally 2026-03-28; phases `69` through `72` are
complete and the milestone audit is written.

---

## Executable Milestones Behind v2.19

### v2.19 Bonded Autonomy and Facility Execution

**Executable phases prepared:** 85-88
**Goal:** Introduce reserve locks, bond contracts, autonomy tier gates, and
loss or recovery state so ARC can enforce capital-backed autonomy at runtime.

### v2.20 Liability Marketplace and Claims Network

**Executable phases prepared:** 89-92
**Goal:** Add provider registry, quote and bind artifacts, claim packages, and
dispute workflows so ARC can honestly claim liability-market orchestration over
canonical evidence.
**Current state:** phases `89` through `92` are complete locally; `v2.20`
closed the bounded research-completion ladder before the post-`v2.20` full
endgame sequence was activated at `v2.21`.

---

## Earlier Completed Milestone

### v2.12 Workload Identity and Attestation Verification Bridges (Completed)

**Executable phases:** 57-60

**Why this milestone mattered:** ARC's next research-driven gap after
portable credential interop is concrete workload identity and attestation
verification bridging. The roadmap now carries detailed executable phase
definitions for phases `57` through `60`, and that workload is now complete
locally.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on SPIFFE/SVID, workload identity, and
  attestation-backed runtime trust
- `crates/arc-core/src/lib.rs` on current SPIFFE-like identifiers being
  treated as opaque strings
- `crates/arc-core/src/capability.rs` on normalized runtime-attestation
  evidence
- `docs/A2A_ADAPTER_GUIDE.md` on current mutual-TLS support at the A2A edge

**Key intended outcomes:**
- explicit SPIFFE/SVID-style workload identity mapping into ARC policy
- concrete cloud or vendor attestation verifier bridges
- fail-closed attestation trust policy and runtime-assurance rebinding
- qualification and operator runbooks for verifier failure and replay
  boundaries

**Completion status:** complete locally 2026-03-28.

---

## Previous Completed Milestone

### v2.11 Portable Credential Interop and Wallet Distribution (Completed)

**Executable phases:** 53-56

**Why this milestone mattered:** ARC's research-driven next gap after
underwriting was portable credential interop. `v2.11` closed that gap
conservatively with OID4VCI-compatible issuance, portable lifecycle
distribution, holder-facing presentation transport, and one raw-HTTP external
compatibility proof.

**Research basis:**
- `docs/research/DEEP_RESEARCH_1.md` on VC portability, OID4VCI, and passport
  distribution
- `crates/arc-credentials/src/lib.rs` on the current intentionally simple
  ARC-native credential format
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` on the current
  no-global-registry and no-public-wallet-distribution boundaries
- `spec/PROTOCOL.md` on current portable-wallet and identity propagation gaps

**Key intended outcomes:**
- interoperable credential issuance flows beyond ARC-native file delivery
- portable status, revocation, and supersession semantics for wallet ecosystems
- holder-facing presentation and transport contracts
- external verifier compatibility proof without weakening current trust
  boundaries

**Completion status:** complete locally 2026-03-28.

---

## Earlier Completed Milestones

## v2.9 Economic Evidence and Authorization Context Interop (Completed: 2026-03-27)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Standardized generic metered-billing quote, cap, and post-execution evidence
  semantics for non-payment-rail tools.
- Added replay-safe mutable reconciliation state and operator reporting for
  post-execution economic truth without mutating signed receipts.
- Added derived authorization-context and delegated call-chain projection from
  signed governed receipts for IAM and partner consumption.
- Published focused qualification, operator, and partner-facing economic
  interop materials and closed the milestone with an explicit audit.

---

## v2.10 Underwriting and Risk Decisioning (Completed: 2026-03-27)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Shipped signed underwriting-policy inputs plus deterministic runtime
  underwriting decisions over canonical ARC evidence.
- Shipped persisted signed underwriting decisions with explicit budget,
  premium, supersession, and appeal semantics without mutating canonical
  receipt truth.
- Shipped non-mutating underwriting simulation so operators can compare
  baseline and proposed policy outcomes before issuing new signed decisions.
- Updated qualification, release-candidate, and partner-proof materials and
  closed the milestone with an explicit audit.

---

## v2.8 Risk, Attestation, and Launch Closure (Completed: 2026-03-27)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Shipped signed insurer-facing behavioral feeds plus runtime-assurance-aware
  issuance and governed-execution constraints.
- Closed the executable formal/spec launch boundary and reran the full release
  qualification lane successfully.
- Published a partner-proof package and updated release, observability,
  operations, and standards-facing docs to the current ARC surface.
- Closed `v2.8` with an explicit local-go/external-release-hold decision
  contract instead of a vague candidate posture.

---

## v2.7 Portable Trust, Certification, and Federation Maturity (Completed: 2026-03-26)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Propagated enterprise identity provenance through portable credentials,
  federated issuance, and verifier flows without silently widening trust.
- Made passport lifecycle state, status distribution, revocation, and
  supersession explicit for operators and relying parties.
- Turned certification into a multi-operator discovery surface with truthful
  supersession and revocation semantics.
- Added conservative cross-org imported-trust signals with explicit evidence
  provenance and policy-visible attenuation.

---

## v2.5 ARC Rename and Identity Realignment (Completed: 2026-03-26)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Made ARC the primary package, CLI, SDK, release, and operator identity while
  reducing remaining Pact-era compatibility to a narrow, explicit set of
  deprecated shims.
- Moved shipped schema/artifact issuance to ARC-primary identifiers where the
  rename contract said the change should happen, while freezing `did:arc`,
  `arc.*`, and `notifications/arc/tool_call_chunk` as the canonical post-rename
  identifiers.
- Rewrote the top-level ARC narrative and reran release qualification plus SDK
  parity on the renamed surface.

---

## v2.6 Governed Transactions and Payment Rails (Completed: 2026-03-26)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Made governed transaction intent and approval evidence first-class across
  policy, runtime, receipts, and operator surfaces.
- Shipped truthful x402 prepaid payment controls and ACP/shared-payment-token
  seller-scoped commerce approvals without collapsing payment truth into tool
  execution truth.
- Added operator-visible settlement backlog reporting, reconciliation actions,
  and explicit invocation-plus-money budget dimensions.

---

## v2.4 Architecture and Runtime Decomposition (Completed: 2026-03-25)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Extracted `arc-control-plane` and `arc-hosted-mcp` so `arc-cli` no longer
  owns long-lived service implementations directly.
- Moved SQLite-backed store, query, report, and export implementations into
  `arc-store-sqlite`, leaving `arc-kernel` closer to an enforcement-core
  facade.
- Split MCP runtime transport into `arc-mcp-edge` and decomposed
  `arc-a2a-adapter` into concern-based modules with compatibility preserved.
- Reduced `arc-credentials`, `arc-reputation`, and `arc-policy` entry files
  to thin facades and added a fail-closed workspace layering guard.

---

## v2.3 Production and Standards (Completed: 2026-03-25)

**Phases completed:** 4 phases, 12 plans, 0 tasks

**Key accomplishments:**
- Shipped source-only release inputs, packaging guards, and a cleaner CLI admin
  ownership boundary.
- Shipped one canonical release-qualification lane covering workspace,
  dashboard, SDK packages, live conformance, and repeat-run trust-cluster
  behavior.
- Shipped supported observability and health contracts for trust-control,
  hosted edges, federation, and A2A diagnostics.
- Shipped protocol v2 alignment, standards-submission draft artifacts, and
  launch-readiness evidence for the production candidate.

---

## v2.2 A2A and Ecosystem Hardening (Completed: 2026-03-25)

**Phases completed:** 4 phases, 12 plans

**Key accomplishments:**
- Shipped explicit A2A request shaping plus fail-closed partner admission and
  clearer operator-visible auth diagnostics.
- Shipped durable A2A task-registry persistence and restart-safe follow-up
  validation tied to the originating partner and interface binding.
- Shipped registry-backed certification publication, lookup, resolution,
  supersession, and revocation across CLI and trust-control.
- Shipped operator docs, regression coverage, and planning traceability for the
  completed v2.2 surfaces.

---

## v2.1 Federation and Verifier Completion (Shipped: 2026-03-24)

**Phases completed:** 4 phases, 15 plans

**Key accomplishments:**
- Shipped enterprise federation administration with provider-backed identity
  normalization, SCIM/SAML surfaces, and policy-visible provenance.
- Shipped signed reusable verifier-policy artifacts plus replay-safe persisted
  challenge state across CLI and remote verifier flows.
- Shipped truthful multi-issuer passport composition with issuer-aware
  evaluation, reporting, and regression coverage.
- Shipped shared-evidence federation analytics across operator reports,
  reputation comparison, CLI, and dashboard surfaces.

---

## v2.0 Agent Economy Foundation (Shipped: 2026-03-24)

**Phases completed:** 6 phases, 19 plans

**Key accomplishments:**
- Shipped monetary budgets, truthful settlement metadata, Merkle checkpoints,
  retention/archival, and receipt analytics.
- Shipped receipt query APIs, operator reporting, compliance evidence export
  and verification, and the receipt dashboard.
- Shipped local reputation scoring, reputation-gated issuance, `did:arc`,
  Agent Passport alpha, verifier evaluation, and challenge-bound presentation
  flows.
- Shipped A2A adapter alpha with streaming, task lifecycle, auth-matrix
  coverage, and identity federation alpha.
- Shipped bilateral evidence-sharing, federated evidence import, portable
  comparison surfaces, and multi-hop cross-org delegation.

---

## v1.0 Closing Cycle (Complete)

**Completed:** 2026-03-20
**Phases:** 6 (all complete, 24 plans executed)

**Summary:** Shipped the protocol foundation: capability-scoped mediation,
fail-closed guards, signed receipts, MCP-compatible edge with
tools/resources/prompts/completions/nested flows/auth/notifications/task
lifecycle, HA distributed trust-control with deterministic leader election,
cross-language conformance (JS/Python), and release qualification.

**Validated requirements:**
- Capability-scoped mediation, guard evaluation, and signed receipts
- MCP-compatible tool, resource, prompt, completion, logging, roots, sampling,
  and elicitation flows
- Live conformance waves against JS and Python peers
- HA trust-control determinism and reliability
- Roots enforced as filesystem boundary
- Remote runtime lifecycle hardening
- Cross-transport task/stream/cancellation semantics
- Unified policy surface (HushSpec canonical, ARC YAML compat)
- Release qualification with conformance + repeat-run trust-cluster proof
