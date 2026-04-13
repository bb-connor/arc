# Standards Positioning Remediation

## Problem

CHIO currently makes comparative and standards-positioning claims that are
broader than the evidence boundary of the shipped repo.

The problem is not that the repo has no interoperability or standards work. It
does. The problem is that the public narrative often collapses five different
things into one undifferentiated "protocol" claim:

1. the native CHIO capability and receipt protocol
2. the CHIO runtime and hosted control-plane product bundle
3. MCP compatibility and mediation
4. A2A compatibility and bridging
5. bounded identity and credential interoperability profiles

Once those layers are merged rhetorically, the repo starts making claims that
sound like:

- CHIO is the only protocol that solves the whole stack
- CHIO can fairly be compared to wire protocols, wallet standards, and payment
  rails as one thing
- CHIO is simultaneously "not a replacement for MCP/A2A" and "able to replace
  MCP in real deployments"
- CHIO passports and federation are general DID/VC interoperability rather than
  ARC-first profile projection with explicit guardrails
- adapter-level compatibility is broad ecosystem interoperability

That framing is unstable. It weakens standards credibility, invites unfair
comparisons, and makes it hard for outsiders to tell what is actually shipped,
what is bounded by design, and what would require major new product work.

## Current Evidence

The repo already contains substantial evidence for a narrower, defensible
position.

### 1. The spec already contains honest boundaries

`spec/PROTOCOL.md` already says the shipped contract does **not** claim:

- generic OID4VP, SIOP, DIDComm, or permissionless wallet-network compatibility
- permissionless public identity or wallet discovery that widens local trust
- a replacement of MCP or A2A at the wire-protocol ecosystem level

It also explicitly describes:

- MCP as a compatibility layer, not a replacement surface
- the A2A adapter as a thin bridge for A2A v1.0.0, not a new A2A standard
- OID4VCI and OID4VP as narrow bridges over ARC passport truth
- `did:arc` as the shipped canonical provenance anchor

That is already the outline of an honest standards story.

### 2. The product has real MCP evidence

The repo has a meaningful MCP compatibility body:

- `README.md` documents the MCP wrapping and hosted edge
- `spec/PROTOCOL.md` defines an MCP-compatible mediation contract
- `tests/conformance/README.md` records live Wave 1 through Wave 5 remote HTTP
  green status across JS, Python, and Go peers

This is strong evidence for:

- MCP mediation
- MCP compatibility for the tested scenario waves
- practical adoptability as a governance layer in front of MCP servers

It is not, by itself, evidence that CHIO is a new universal MCP replacement
standard.

### 3. The product has meaningful but narrower A2A evidence

The repo ships a real A2A adapter:

- `docs/A2A_ADAPTER_GUIDE.md` documents the bridge
- `spec/PROTOCOL.md` defines its contract and explicitly labels it adapter-local
- `crates/arc-a2a-adapter/src/tests.rs` contains local interop-style tests

The repo also explicitly admits the key limitation:

- A2A does not define a native skill selector in `SendMessage`
- the adapter uses `metadata.arc.targetSkillId` as an explicit local convention

This supports an honest claim of bounded A2A interop through a CHIO adapter. It
does not yet support a stronger claim of broad A2A ecosystem interoperability or
of CHIO supplying missing A2A semantics at the standard layer.

### 4. The repo already describes DID/VC scope conservatively in places

The current passport and standards docs already say:

- passports still bind issuer and subject as `did:arc`
- OID4VCI is a transport/delivery layer over ARC passport truth
- OID4VP is a narrow verifier profile, not generic wallet compatibility
- public identity profiles may accept `did:web`, `did:key`, and `did:jwk` only
  as compatibility inputs while retaining `did:arc` provenance

The code supports that narrow reading:

- `crates/arc-did/src/lib.rs` implements `did:arc`
- `crates/arc-credentials/src/oid4vci.rs` fixes issuer and subject DID methods
  to `did:arc`
- `crates/arc-credentials/src/oid4vp.rs` constrains the verifier profile to one
  narrow ARC-specific request/response shape
- `crates/arc-core/src/identity_network.rs` requires public identity artifacts
  to preserve `did:arc` provenance and reference ARC-specific basis artifacts

This is evidence for a bounded ARC-first interoperability profile, not for
general DID/VC neutrality.

### 5. Federation is intentionally bounded

The federation and identity docs already reflect an operator-controlled,
fail-closed model:

- bilateral evidence export/import
- explicit provider-admin registries
- explicit local activation
- conservative imported trust reporting
- no ambient directory trust
- no permissionless public trust widening

That is evidence for bounded interoperability and bounded evidence portability.
It is not evidence for general federated trust or a public identity network in
the stronger standards sense.

### 6. The repo also contains the overclaiming language

The strongest gaps are mostly claim-discipline gaps:

- `docs/COMPETITIVE_LANDSCAPE.md` says ARC is the only protocol that addresses
  all twelve dimensions and says the properties cannot be retrofitted onto
  existing protocols
- the same document compares runtime/product attributes like kernel TCB and
  operator federation alongside protocol-layer properties
- `CLAUDE.md` says ARC replaces MCP
- `docs/ROADMAP_V1.md` says the goal is to be compatible enough to replace MCP
  in real deployments
- `README.md` says CHIO is not a replacement for MCP or A2A

The repo therefore already contains both the honest narrow story and the
overstated broad story at the same time.

## Why Claims Overreach

### 1. Protocol and product boundaries are blurred

CHIO is frequently described as one "protocol" while comparisons quietly rely
on properties of the broader bundle:

- kernel enforcement architecture
- hosted trust-control service
- SQLite/operator stores
- receipt dashboard and admin APIs
- federation registries
- standards/profile artifacts

That is category mixing. A wire protocol should not be compared to a runtime
product bundle unless the comparison is explicitly made at the product/platform
level.

### 2. The MCP story is internally inconsistent

The repo currently says all three of the following:

- CHIO is not a replacement for MCP or A2A
- CHIO wraps MCP and adds governance
- ARC can replace MCP in real deployments

Those can be reconciled only if the project adopts a precise distinction:

- not a replacement for the MCP standard
- can replace a direct/raw MCP deployment architecture in some deployments

Without that distinction, the claim reads as a contradiction.

### 3. The A2A story outruns the adapter evidence

Real interoperability claims need evidence against real external peers and real
standard-defined semantics.

Today the repo demonstrates:

- a functioning adapter
- bounded auth negotiation
- local tests
- explicit adapter-local metadata conventions where A2A lacks a native field

That is useful engineering. It is not enough to support claims that CHIO solves
the A2A standards gap or that it has broad A2A interoperability in the strong
sense.

### 4. DID/VC positioning sounds broader than the actual trust model

If the shipped source of truth remains:

- `did:arc` as the canonical provenance anchor
- ARC-specific passport schemas as the native credential family
- narrow projected OID4VCI/OID4VP bridges
- public identity artifacts that are required to point back to ARC basis refs

then the honest statement is:

- ARC offers bounded profile interoperability over an ARC-native trust model

The dishonest statement is:

- ARC already offers general DID/VC interoperability or a neutral public
  identity network

### 5. Competitive comparisons mix incomparable layers

The current competitive matrix mixes:

- cryptographic identity at protocol level
- platform budgets and payment controls
- runtime/product architecture like kernel TCB
- formal verification status
- federated trust semantics

Some competitors in that matrix are:

- wire protocols
- identity protocols
- payment rails
- SDKs
- cloud frameworks

That can still be a valuable landscape document, but only if it is explicitly
framed as a multi-layer platform comparison. It is not defensible as a clean
"protocol versus protocol" matrix.

### 6. "Only protocol" and "cannot be retrofitted" are too strong

Those phrases require unusually strong proof:

- a clearly delimited comparison class
- a stable protocol definition
- a demonstrated impossibility or at least a rigorous architectural argument
- evidence that no comparison target already offers equivalent capability by a
  different composition

The repo does not currently provide that level of evidence. In fact, the
product's own MCP and A2A mediation story is itself evidence that some desired
properties can be layered around existing protocols.

### 7. Bounded interoperability is not being named consistently

The spec and standards docs are strongest when they say:

- narrow bridge
- bounded profile
- compatibility input
- operator-scoped
- fail-closed
- no ambient trust widening

The README and competitive docs are weaker when they collapse those constraints
into broader phrases like:

- portable across trust boundaries
- cross-org federated trust
- public identity network
- interoperable standard

The missing piece is a top-level terminology contract that keeps all docs using
the same boundary words.

## Target End-State

The goal should not be to keep broad claims and merely soften the footnotes. The
goal should be to make the standards story structurally defensible.

That requires three explicit claim layers.

### Layer 1: Native CHIO Protocol Claims

These are claims about CHIO's own normative core:

- capability and receipt semantics
- fail-closed kernel contract
- signed CHIO-native artifacts
- native `did:arc` identity and ARC passport truth
- native control-plane and artifact schemas

This layer may use strong protocol language because it is talking about CHIO's
own semantics.

### Layer 2: Compatibility and Bridge Claims

These are claims about CHIO mediation or adapter behavior over third-party
standards:

- MCP-compatible mediation
- A2A v1.0 bridge
- bounded OID4VCI issuance profile
- bounded OID4VP verifier profile
- bounded public identity-profile and wallet-routing contracts

This layer must use compatibility language, not replacement language.

### Layer 3: Product/Platform Claims

These are claims about the full system bundle:

- hosted trust-control
- operator registries
- dashboards and admin APIs
- federation tooling
- qualification matrices
- deployment and adoption posture

This layer may compare CHIO to broader platforms, but only when clearly labeled
as a platform or product-bundle comparison.

If the project wants stronger standards claims beyond that, the end-state would
require:

- external interop matrices for MCP and A2A using real partner implementations
- broader DID/VC qualification across non-ARC issuers, holders, and verifiers
- an identity trust model that does not require `did:arc` as the canonical
  provenance anchor for all interoperable flows
- a clean public standards profile family with governance independent enough to
  justify "standard" language rather than "ARC-documented profile"

That is a much larger program than a docs cleanup.

## Required Product/Docs/Standards Changes

### 1. Create a claim registry and terminology contract

Add one canonical document, for example `docs/CLAIM_BOUNDARIES.md`, that defines
approved claim classes:

- `native_protocol`
- `compatibility_bridge`
- `product_platform`
- `research_direction`

For each class, define approved and disallowed phrases.

Examples:

- approved: "MCP-compatible mediation layer"
- disallowed: "replaces MCP" unless explicitly scoped to deployment topology
- approved: "bounded OID4VP verifier profile"
- disallowed: "generic OID4VP interoperability"
- approved: "portable evidence under explicit bilateral federation policy"
- disallowed: "general federated trust" unless that is actually shipped

This document should become the source of truth for README, spec, roadmap,
competitive docs, and release materials.

### 2. Split the spec into normative core versus compatibility profiles

`spec/PROTOCOL.md` already contains much of this separation informally. Make it
explicit in structure.

Recommended split:

- `spec/CORE_PROTOCOL.md`
  Native capability, receipt, revocation, budget, and kernel semantics
- `spec/MCP_COMPATIBILITY.md`
  MCP mediation contract and conformance boundary
- `spec/A2A_COMPATIBILITY.md`
  A2A bridge contract and explicit adapter-local conventions
- `spec/IDENTITY_PROFILES.md`
  `did:arc`, passports, OID4VCI/OID4VP, public identity/profile artifacts
- `spec/FEDERATION_BOUNDARIES.md`
  explicit evidence-sharing and local-activation limits

The existing monolithic spec can remain temporarily as an index, but the
standards story gets much cleaner once each layer has its own normative home.

### 3. Rewrite the competitive landscape as three separate matrices

Replace the single mixed matrix with:

- `Protocol Core Matrix`
  Compare CHIO-native protocol semantics to UCAN, ANP, AIMS, etc.
- `Compatibility/Adapter Matrix`
  Compare MCP and A2A mediation scope, tested coverage, and adoption posture
- `Platform Bundle Matrix`
  Compare CHIO as a product/system bundle to cloud frameworks, payment rails,
  and broader agent-control platforms

Rules for the new matrices:

- no mixing protocol-only claims with product/runtime properties in the same
  table unless the table is explicitly platform-scoped
- every row must identify its layer: protocol, compatibility, product
- every "yes" cell must cite shipped evidence or qualification artifacts
- roadmapped work must not appear as a shipped "yes"
- "only protocol" claims are banned unless the comparison class and evidence
  are rigorous enough to survive external review

### 4. Resolve MCP positioning with one precise formulation

Adopt the following product rule:

- CHIO does not replace the MCP standard
- CHIO can replace direct/raw MCP deployment patterns by interposing a governed
  MCP-compatible edge
- CHIO may eventually become the preferred security wrapper for MCP-class
  deployments, but that is an adoption claim, not a standards claim

Required doc changes:

- remove "replaces MCP" from `CLAUDE.md`
- revise `docs/ROADMAP_V1.md` so "replace MCP in real deployments" becomes
  "replace raw MCP deployment architectures in security-sensitive deployments"
- keep README language aligned with that formulation

### 5. Resolve A2A positioning with explicit adapter language

Adopt the following rule:

- CHIO does not extend the A2A standard
- CHIO ships a bridge to A2A v1.0 with explicit adapter-local conventions where
  A2A lacks native fields
- interoperability claims are limited to the tested A2A bindings, auth modes,
  and task-follow-up flows in the qualification matrix

Required product work if stronger A2A claims are desired:

- add a public A2A qualification matrix against multiple external A2A servers
- document each adapter-local convention and prove fail-closed behavior when the
  peer cannot satisfy it
- avoid implying that adapter metadata conventions are A2A-native semantics

### 6. Reframe DID/VC interoperability as profile-bound

Adopt the following standards rule:

- ARC/CHIO ships an ARC-native identity and passport system
- it exports bounded OID4VCI and OID4VP profiles over that truth surface
- external DID methods may appear as compatibility inputs or mapped identities
  only within explicitly qualified profiles
- ARC must not claim generic DID/VC interoperability until non-ARC issuer,
  holder, and verifier combinations are first-class, qualified, and not
  anchored back to `did:arc` as universal provenance truth

Required docs changes:

- replace "portable across trust boundaries" with
  "portable under explicit bilateral policy and bounded profile contracts"
- replace "public identity network" with
  "bounded public identity-profile and wallet-routing contract"
- explicitly distinguish:
  - native truth
  - projected credential profiles
  - compatibility inputs
  - local trust activation

### 7. Decide whether the project wants genuine broader DID/VC claims

If the answer is no:

- keep the bounded-profile story
- stop describing it as general interoperability

If the answer is yes:

- implement general DID method resolution and trust policy beyond `did:arc`
- support non-ARC issuer/subject methods as first-class truth, not only mapped
  compatibility inputs
- broaden OID4VCI and OID4VP to multi-credential, multi-format, multi-issuer
  qualification
- qualify real third-party wallets and verifiers
- define which parts remain ARC policy and which become standards-profile rules

This is an identity-program roadmap, not a simple patch.

### 8. Define "bounded interoperability" as a first-class product concept

Add a shared definition used across all docs:

`bounded interoperability` means:

- CHIO can communicate or exchange artifacts with an external standard surface
- only within an explicitly documented profile
- with explicit trust roots
- with explicit unsupported-shape rejection
- without ambient trust widening
- and with local policy activation remaining authoritative

Then require all interop docs to state:

- what is compatible
- what is intentionally unsupported
- what evidence proves compatibility
- what still remains CHIO-private truth

### 9. Add external qualification artifacts for every public interop claim

For each major compatibility claim, add a checked-in qualification matrix:

- `MCP_COMPATIBILITY_MATRIX.md`
  with per-wave peer coverage and unsupported items
- `A2A_COMPATIBILITY_MATRIX.md`
  with real external peers and adapter-local gaps
- `IDENTITY_INTEROP_MATRIX.md`
  with issuer/verifier/wallet combinations, supported formats, and fail-closed
  cases
- `FEDERATION_BOUNDARY_MATRIX.md`
  with explicit import/export activation and non-goal cases

The key rule is simple:

- no top-level interoperability claim without a public qualification artifact

### 10. Narrow the README to evidence-based claims

The README should become the cleanest expression of the honest story.

Recommended replacements:

- from "trust-and-economics control plane and protocol" to
  "governed action runtime with a native protocol and compatibility layers"
- from "portable credential system" to
  "ARC-native passport and bounded credential interoperability profiles"
- from "A2A interop" badge to
  "A2A bridge" unless there is broader ecosystem qualification
- from sweeping comparative language to
  short statements with explicit boundaries and links to qualification docs

### 11. Add standards-governance discipline

If the project wants to talk like a standards effort, it needs standards
discipline.

Required changes:

- every public profile gets a status label: experimental, bounded, candidate,
  stable
- every profile lists:
  - trust assumptions
  - non-goals
  - conformance requirements
  - interoperability evidence
- product features that depend on operator-local policy must be labeled as such
- marketing copy must not silently promote an operator-local policy profile into
  a neutral standard

## Validation Plan

### 1. Documentation consistency audit

Create a repository-wide audit for phrases such as:

- replaces MCP
- only protocol
- interoperable standard
- portable across trust boundaries
- public identity network
- federated trust
- A2A interop

Every hit must be rewritten or explicitly justified by the claim registry.

### 2. Evidence mapping

For every top-level claim in README, competitive docs, and standards docs:

- identify the evidence class
- identify the source artifact
- identify whether the claim is native, compatibility, or product
- identify whether the claim is shipped or aspirational

Any claim that cannot be mapped gets downgraded or removed.

### 3. External interoperability qualification

Add reproducible qualification runs for:

- MCP peers already in the repo
- at least two external A2A server implementations
- at least one external wallet/verifier lane for the narrow OID4VP profile if
  public interoperability is claimed
- representative fail-closed negative cases for unsupported shapes

These results should be published as generated artifacts, not prose assertions.

### 4. Boundary review

Run one explicit internal review that asks:

- is this statement about the CHIO native protocol?
- is it about an adapter?
- is it about the product bundle?
- is it about a research direction?

If reviewers disagree on classification, the claim is not clear enough to ship.

### 5. Release gate

Add a lightweight release gate:

- no release if the claim-registry linter finds banned phrases
- no release if qualification matrices are stale relative to the release tag
- no release if README/spec/competitive docs disagree on MCP/A2A/DID scope

## Milestones

### Milestone 0: Immediate claim containment

- remove contradictory MCP replacement language
- remove or rewrite "only protocol" language
- rename A2A claims from interop to bridge where evidence is adapter-local
- narrow passport/federation/public identity wording to bounded-profile terms

Exit criteria:

- README, competitive docs, roadmap, and internal top-level docs no longer
  contradict each other

### Milestone 1: Layered standards architecture

- publish claim registry
- split normative core versus compatibility/profile docs
- create separate matrices for core protocol, compatibility, and platform
- label all public profiles with status and non-goals

Exit criteria:

- every public standards/comparison doc uses the same layer vocabulary

### Milestone 2: Qualification-backed compatibility

- publish checked-in MCP compatibility matrix
- publish checked-in A2A compatibility matrix
- publish identity interop matrix for the bounded profiles
- add negative/fail-closed qualification scenarios

Exit criteria:

- every compatibility claim in README points to a concrete matrix

### Milestone 3: Decide identity ambition

Choose one path:

- `bounded-profile path`
  Keep ARC-native truth and market it honestly
- `broader-interop path`
  fund the significant product work required for more general DID/VC claims

Exit criteria:

- the project has one explicit and coherent identity story

### Milestone 4: Stronger standards claims, if still desired

Only after the above:

- broaden external interop partners
- qualify non-ARC issuers/verifiers/wallets if applicable
- revisit comparative claims with layer-clean matrices and citations

Exit criteria:

- stronger claims become evidence-backed rather than rhetorical

## Acceptance Criteria

This hole is successfully plugged only when all of the following are true.

- A reader can tell, from the README alone, what is native CHIO protocol, what
  is compatibility/adapter behavior, and what is product bundle behavior.
- No top-level doc simultaneously says CHIO both replaces and does not replace
  MCP/A2A.
- A2A claims are limited to the exact tested adapter surface unless broader
  external evidence exists.
- DID/VC/passport claims consistently describe the shipped model as ARC-native
  truth with bounded interop profiles unless the product has genuinely moved
  beyond that.
- Competitive comparisons are partitioned by comparison layer and no longer mix
  protocol and platform properties as if they were one category.
- Every "interoperable" or "compatible" claim links to a qualification artifact.
- The phrase "only protocol" does not appear unless there is a rigorous,
  layer-clean proof standard behind it.
- The phrase "bounded interoperability" is defined once and used consistently.
- Release qualification fails if public docs drift from the claim registry.

## Risks/Non-Goals

### Risks

- Narrowing claims will make the project sound less grand in the short term.
  That is acceptable. Credibility compounds faster than hype.
- Splitting protocol, compatibility, and product docs will add documentation
  maintenance overhead.
- If the team really wants broader DID/VC or A2A standards claims, the required
  product work is substantial and may compete with core runtime priorities.
- Competitive docs may become less rhetorically punchy once apples-to-oranges
  comparisons are removed.

### Non-Goals

- This memo does not recommend abandoning MCP or A2A compatibility work.
- This memo does not recommend abandoning ARC-native identity or passports.
- This memo does not require CHIO to become a neutral third-party standard
  immediately.
- This memo does not require solving universal DID/VC interoperability unless
  the project explicitly chooses that path.
- This memo does not claim that narrower wording alone is sufficient for strong
  future standards claims; real external qualification and product work are
  still required.

The practical objective is simpler: make every public claim true on its own
terms, and make the standards story legible enough that a skeptical external
reviewer can tell exactly what CHIO is, what it wraps, what it projects, and
what remains intentionally bounded.
