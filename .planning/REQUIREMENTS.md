# Requirements: ARC

**Defined:** 2026-03-27
**Latest completed milestone:** v2.22 Wallet Exchange, Identity Assertions, and
Sender-Constrained Authorization (completed locally 2026-03-30)
**Active milestone:** v2.23 Common Appraisal Vocabulary and External Result
Interop
**Next milestone after active:** v2.24 Verifier Federation, Cross-Issuer
Portability, and Discovery
**Core Value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust across organizational boundaries.

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

- [ ] **APPX-01**: ARC defines one versioned common appraisal contract that
  separates evidence identity, normalized claims, vendor claims, verifier
  statement, provenance inputs, and local ARC policy outcome.
- [ ] **APPX-02**: ARC defines one versioned normalized claim vocabulary and
  reason taxonomy that more than one verifier family can emit.
- [ ] **APPX-03**: ARC can export and import signed appraisal results while
  keeping external verifier provenance and local policy decision separate.
- [ ] **APPX-04**: Existing Azure, AWS, and Google bridges remain backward-
  compatible and fail closed during the common-contract migration.
- [ ] **APPX-05**: Qualification proves mixed-provider portability and honest
  documentation boundaries for external appraisal-result interop.

### v2.24 Verifier Federation, Cross-Issuer Portability, and Discovery

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` implies cross-issuer
portability, broader verifier ecosystems, and public discovery layers as part
of the open trust substrate.
**Current boundary references:** `docs/CREDENTIAL_INTEROP_GUIDE.md`,
`docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` describe the gap
between today's bounded bridges and a federated, discovery-capable substrate.

- [ ] **FEDX-01**: ARC supports cross-issuer portfolios, trust packs, and
  migration or supersession semantics without inventing synthetic global trust.
- [ ] **FEDX-02**: ARC defines verifier descriptors, trust bundles, and
  endorsement or reference-value distribution with provenance and rotation
  semantics.
- [ ] **FEDX-03**: ARC publishes public issuer and verifier discovery surfaces
  with transparency and explicit local import policy.
- [ ] **FEDX-04**: ARC supports additional provider or verifier families on the
  same common appraisal contract and portable identity substrate.
- [ ] **FEDX-05**: Discovery and federation never auto-admit runtime trust;
  local policy activation remains explicit and auditable.

### v2.25 Live Capital Allocation and Escrow Execution

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` pushes from underwriting
and credit into actual agent credit allocation and capital-backed autonomy.
**Current boundary references:** `spec/PROTOCOL.md`,
`docs/release/RELEASE_CANDIDATE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` all make clear that
ARC currently stops at bounded facility and bond policy rather than live
capital execution.

- [ ] **CAPX-01**: ARC defines live capital-book and source-of-funds artifacts
  with explicit committed, held, drawn, disbursed, released, repaid, and
  impaired state.
- [ ] **CAPX-02**: ARC defines custody-neutral escrow or reserve instruction
  artifacts with separate intended and externally reconciled state.
- [ ] **CAPX-03**: Governed actions can be mapped to one explicit source of
  funds and allocation decision under bounded policy.
- [ ] **CAPX-04**: Regulated roles, authority chains, and execution windows are
  explicit whenever ARC starts moving or locking live capital.
- [ ] **CAPX-05**: Live capital execution remains simulation-first and fail
  closed on mixed-currency, missing-counterparty, or reconciliation mismatch
  conditions.

### v2.26 Reserve Control, Autonomous Pricing, and Claims Payment

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` goes beyond credit and
bounded liability artifacts into bonded autonomy, pricing, coverage, and
market-backed loss handling.
**Current boundary references:** `spec/PROTOCOL.md`,
`docs/release/RELEASE_CANDIDATE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` define the current
absence of live slashing, auto-bind, and automatic claims payment.

- [ ] **LIVEX-01**: ARC can execute reserve impairment, release, and slash
  controls under explicit evidence, appeal, and reconciliation rules.
- [ ] **LIVEX-02**: ARC supports delegated pricing authority and automatic
  coverage binding only inside one explicit provider or regulated-role envelope.
- [ ] **LIVEX-03**: ARC supports a narrow automatic claims-payment lane with
  payout instructions, payout receipts, and external reconciliation artifacts.
- [ ] **LIVEX-04**: ARC can clear recoveries, reinsurance obligations, or
  facility reimbursements across counterparties without hidden state.
- [ ] **LIVEX-05**: Every live-money transition is explicitly role-attributed,
  evidence-linked, and fail closed on counterparty mismatch or stale authority.

### v2.27 Open Registry, Trust Activation, and Governance Network

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` points toward broader
registry, governance, and market-discipline structure, not only curated
discovery.
**Current boundary references:** `spec/PROTOCOL.md`,
`docs/release/RELEASE_CANDIDATE.md`, and
`.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md` all keep today's
discovery surfaces public-but-curated and non-auto-trusting.

- [ ] **OPENX-01**: ARC defines a generic listing and namespace model for tools,
  issuers, verifiers, providers, and future market actors.
- [ ] **OPENX-02**: Origin operators, mirrors, indexers, ranked search, and
  freshness metadata are explicit and reproducible.
- [ ] **OPENX-03**: ARC defines trust-activation artifacts and open admission
  classes so visibility never equals runtime admission.
- [ ] **OPENX-04**: Governance charters, dispute escalation, sanctions, freezes,
  and appeals can travel across operators with signed case artifacts.
- [ ] **OPENX-05**: Open publish lanes remain bounded by economics, identity, or
  bond requirements and fail closed under abuse or unverifiable evidence.

### v2.28 Portable Reputation, Marketplace Economics, and Endgame Qualification

**Research basis:** `docs/research/DEEP_RESEARCH_1.md` treats the final market
thesis as one governed ecosystem with portable evidence, market discipline, and
liability or abuse controls rather than a universal trust oracle.
**Current boundary references:** `.planning/research/POST_V2_20_FULL_ENDGAME_SYNTHESIS.md`
and `docs/release/RELEASE_CANDIDATE.md` define the remaining gap between
today's bounded control plane and the full open-market endgame claim.

- [ ] **ENDX-01**: ARC supports portable reputation and negative-event exchange
  with issuer provenance and local weighting rather than a global trust score.
- [ ] **ENDX-02**: ARC defines marketplace fee schedules, publisher or dispute
  bonds, slashing, and abuse-resistance economics.
- [ ] **ENDX-03**: Qualification proves adversarial multi-operator open-market
  behavior without collapsing visibility into trust.
- [ ] **ENDX-04**: Partner proof, release audit, and protocol docs are updated
  to claim the widened endgame honestly and explicitly.
- [ ] **ENDX-05**: ARC still preserves explicit non-goals against universal
  trust oracles, automatic cross-issuer scores, and ambient trust widening.

## Out of Scope

| Feature | Reason |
|---------|--------|
| ARC as a direct payment rail | ARC continues to bridge to payment rails and meter them truthfully rather than becoming a settlement network itself. |
| Synthetic universal trust oracle | Imported trust, portable reputation, and cross-issuer evidence remain provenance-preserving and locally weighted instead of collapsing into one global truth source. |
| Ambient runtime trust from discovery visibility | Even the planned open registry and discovery lanes must require explicit local trust activation and never treat visibility as admission. |
| Automatic authority widening from identity, attestation, or imported evidence | Enterprise identity, workload evidence, and federated artifacts may inform evaluation, but they must not silently expand rights, billing scope, or runtime trust. |
| ARC as an implicit regulated actor of record | Later milestones may orchestrate regulated-role execution profiles, but the role performing pricing, custody, claims payment, or collection must remain explicit rather than being assumed from generic ARC operation. |
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
| APPX-01 | Phase 101 | Planned |
| APPX-02 | Phase 102 | Planned |
| APPX-03 | Phase 103 | Planned |
| APPX-04 | Phase 103 | Planned |
| APPX-05 | Phase 104 | Planned |
| FEDX-01 | Phase 105 | Planned |
| FEDX-02 | Phase 106 | Planned |
| FEDX-03 | Phase 107 | Planned |
| FEDX-04 | Phase 108 | Planned |
| FEDX-05 | Phase 107 | Planned |
| CAPX-01 | Phase 109 | Planned |
| CAPX-02 | Phase 110 | Planned |
| CAPX-03 | Phase 111 | Planned |
| CAPX-04 | Phase 112 | Planned |
| CAPX-05 | Phase 112 | Planned |
| LIVEX-01 | Phase 113 | Planned |
| LIVEX-02 | Phase 114 | Planned |
| LIVEX-03 | Phase 115 | Planned |
| LIVEX-04 | Phase 116 | Planned |
| LIVEX-05 | Phase 116 | Planned |
| OPENX-01 | Phase 117 | Planned |
| OPENX-02 | Phase 118 | Planned |
| OPENX-03 | Phase 119 | Planned |
| OPENX-04 | Phase 120 | Planned |
| OPENX-05 | Phase 119 | Planned |
| ENDX-01 | Phase 121 | Planned |
| ENDX-02 | Phase 122 | Planned |
| ENDX-03 | Phase 123 | Planned |
| ENDX-04 | Phase 124 | Planned |
| ENDX-05 | Phase 124 | Planned |

**Coverage:**
- Completed requirements tracked here: 74
- Active and planned requirements: 35
- Mapped to phases: 109
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-27*
*Last updated: 2026-03-30 after activating v2.23 through v2.28 into executable phase work*
