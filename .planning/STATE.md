---
gsd_state_version: 1.0
milestone: v2.23
milestone_name: Common Appraisal Vocabulary and External Result Interop
status: in_progress
stopped_at: phase 101 ready after activating remaining milestones through v2.28
last_updated: "2026-03-30T06:38:44Z"
last_activity: 2026-03-30 -- activated v2.23 through v2.28 into executable phase detail
progress:
  total_phases: 4
  completed_phases: 0
  total_plans: 12
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-30)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** `v2.23 Common Appraisal Vocabulary and External Result
Interop` is now active.
Phases `81` through `92` are complete locally, and the existing
hosted-release observation hold from `v2.8` still remains for public
publication of the already locally qualified release. The post-`v2.20`
endgame ladder is now defined through `v2.28`, and phases `101` through `124`
are now decomposed into executable phase detail on disk so autonomous
execution can run straight through the remaining roadmap.

## Current Position

Phase: `101` ready
Plan: `v2.22` is complete locally, and `v2.23` is now the active milestone.
ARC's next layer externalizes the current multi-cloud appraisal bridge into a
versioned result contract with normalized claims, reason taxonomy, and
explicit import/export semantics. Later milestones `v2.24` through `v2.28`
are also activated and executable on disk, so no additional activation step
is required after phase `104`.
The normalized post-`v2.20` sequence still runs from `v2.22` through `v2.28`
across wallet exchange, appraisal federation, live capital execution, and
open-market governance.
Status: `v2.5` through `v2.22` are complete locally. `v2.23` is active, and
`v2.24` through `v2.28` are executable next milestones.
Last activity: 2026-03-30 -- activated phases `101` through `124`

Progress: [----------] 0%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans, plus substantial post-milestone
  portable-trust execution beyond the original archive
- v2.1: complete (15/15 plans)
- v2.2: complete (12/12 plans executed)
- v2.3: complete and archived (12/12 plans executed)
- v2.4: complete and archived (12/12 plans executed)
- v2.5: complete and archived (12/12 plans executed)
- v2.6: complete and archived (12/12 plans executed)
- v2.7: complete (12/12 plans executed)
- v2.8: complete (12/12 plans executed)

## Accumulated Context

### Decisions

- Imported federated evidence remains isolated from native local receipt tables;
  foreign receipts are not mixed into local receipt history.
- Multi-hop federated lineage uses explicit bridge records rather than foreign
  parent references in native local lineage tables.
- Shared remote evidence is operator-visible through reference reports rather
  than direct foreign receipt ingestion.
- Portable verifier policies ship as signed reusable artifacts with
  registry-backed references and replay-safe verifier challenge persistence.
- Passport verification, evaluation, and presentation support truthful
  multi-issuer bundles for one subject without inventing aggregate cross-issuer
  scores.
- Passport issuance now includes one OID4VCI-compatible pre-authorized-code
  delivery lane for the existing `AgentPassport` artifact without changing
  `did:arc` as the credential trust anchor.
- Portable lifecycle distribution now projects from the existing passport
  lifecycle registry into issuer metadata, credential-response sidecars, and a
  public read-only trust-control resolve path without creating a second mutable
  truth source.
- Holder-facing passport transport is now bounded to public fetch and submit
  routes over stored verifier challenges; admin challenge creation and policy
  control remain authenticated control-plane actions.
- Identity federation supports provider-admin, SCIM, SAML, and policy-visible
  enterprise identity context, but enterprise identity must never silently
  widen trust or billing authority.
- A2A partner hardening includes explicit request shaping, fail-closed partner
  admission, and a durable task registry for restart-safe follow-up recovery.
- Certification discovery uses an explicit operator network with public
  read-only per-operator resolve, authenticated fan-out publication, and
  provenance-preserving aggregation instead of a global mutable registry.
- Imported cross-org reputation surfaces as explicit `importedTrust` signals
  with issuer/share provenance, proof and age guardrails, and attenuated scores
  that do not rewrite native local reputation history.
- Signed behavioral-feed exports expose canonical receipt, settlement,
  governed-action, reputation, and shared-evidence data for external risk
  consumers without claiming to be an underwriting model.
- Runtime attestation is normalized into explicit assurance tiers that can cap
  issuance scope, require stronger evaluation posture, and rebind
  economically-sensitive grants back to governed execution.
- Executable diff-tests, runtime/conformance lanes, and full release
  qualification are the current shipped launch evidence boundary; theorem-prover
  completion beyond that remains deferred.
- The launch decision contract is explicit: local evidence can produce a
  technical go, but external tag/publication still waits on hosted workflow
  observation and operator sign-off.
- The remaining Pact-era identifiers are intentional compatibility freezes, not
  incomplete rename work: `DidPact`, `NativePactServiceBuilder`,
  `NativePactService`, `pactToolStreaming`, and `pactToolStream`.
- The research-driven post-`v2.8` sequence is explicit:
  `v2.9` standardizes economic evidence and authorization context,
  `v2.10` productizes underwriting decisions,
  `v2.11` expands portable credential interop without inventing global trust,
  and `v2.12` adds concrete workload-identity and attestation verifier
  bridges.
- `v2.9` comes before underwriting because `docs/research/DEEP_RESEARCH_1.md`
  treats standardized cost semantics and transaction context as prerequisites
  for runtime underwriting.
- Metered billing quotes, execution receipts, and later usage evidence are
  separate truths: ARC signs each surface explicitly rather than collapsing
  quote, observed execution, and post-execution billing into one mutable
  record.
- External metered-cost evidence is persisted and reconciled through mutable
  sidecar state keyed by `receipt_id`, with replay-safe evidence identifiers
  and explicit operator reconciliation state instead of receipt mutation.
- External authorization-context export is derived from signed governed
  receipts and cannot be edited independently from approval-bound intent
  state.
- `v2.9` is complete and archived as the substrate milestone for
  underwriting.
- `v2.10` is now complete locally with simulation, qualification, and partner
  proof evidence.
- `v2.11` is now complete locally, including one raw-HTTP external portable
  credential interop proof lane.
- `v2.12` is complete locally with one Azure-first verifier bridge, explicit
  trusted-verifier policy, and qualification closure, but the broader
  multi-cloud appraisal ecosystem remains future work.
- `v2.11` and `v2.12` must preserve the conservative trust boundaries already
  documented in `spec/PROTOCOL.md` and
  `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`.
- Phase `57` standardized one explicit SPIFFE/SVID-style workload-identity
  mapping contract, bound it into issuance, governed receipts, and
  policy-visible attestation context, and kept non-SPIFFE runtime identity
  opaque for compatibility.
- Phase `58` added the first concrete verifier bridge for Azure Attestation
  JWTs, with explicit issuer and signing-key trust, attestation-type allowlists,
  optional SPIFFE workload-identity projection, and a conservative `attested`
  cap pending trust-policy rebinding.
- Phase `59` made verifier trust explicit through `trusted_verifiers`,
  rebinding trusted attestation evidence into effective runtime-assurance tiers
  and denying stale or unmatched verifier evidence fail closed.
- Phase `60` added qualification evidence, workload-identity runbook
  guidance, release-proof updates, and explicit milestone audit closure for the
  verifier boundary.
- Phase `69` defined the canonical multi-cloud appraisal contract and verifier
  adapter interface that all later attestation families must use.
- Phase `70` added AWS Nitro as the first non-Azure verifier family with
  certificate-anchored measurement validation and conservative normalization.
- Phase `71` added Google Confidential VM as the second non-Azure verifier
  family, made trusted-verifier rules appraisal-aware through verifier-family
  and required-assertion matching, and threaded the accepted schema plus
  verifier family into governed receipts and underwriting posture.
- Phase `72` closed `v2.15` by adding a signed runtime-attestation appraisal
  export surface, multi-cloud qualification evidence, and honest protocol,
  release, runbook, and partner-boundary updates.
- Phase `73` formalized ARC's first OAuth-family authorization profile over
  governed receipt truth, made the authorization-context report declare that
  profile explicitly, and rejects malformed profile projections fail closed.
- Phase `75` added machine-readable authorization-profile metadata,
  reviewer-pack evidence bundles, and operator-facing `trust
  authorization-context` commands so enterprise IAM teams can inspect the ARC
  profile without bespoke joins.
- Phase `76` closed `v2.16` with exact qualification over authorization
  metadata, reviewer packs, sender binding, incomplete assurance projection,
  and delegated call-chain integrity, then updated the public release boundary
  honestly.
- Underwriting decisions must remain explicit signed artifacts separate from
  canonical execution receipts and from the insurer-facing behavioral feed.
- Phase `50` added the deterministic underwriting-decision report over
  canonical evidence.
- Phase `51` added separate signed underwriting decision artifacts, projected
  lifecycle state, premium outputs, and appeal records without mutating
  canonical receipt truth.
- Phase `52` added non-mutating underwriting simulation, underwriting-aware
  release and partner docs, and explicit milestone audit closure.
- The post-`v2.12` research-completion ladder is now explicit:
  `v2.13` closes standards-native credential format and lifecycle gaps,
  `v2.14` adds OID4VP verifier and wallet interop,
  `v2.15` adds multi-cloud attestation appraisal,
  `v2.16` adds enterprise IAM standards profiles,
  `v2.17` widens certification into a governed public marketplace,
  `v2.18` adds credit and exposure state,
  `v2.19` adds bonded autonomy, and
  `v2.20` closes the liability-market and claims-network endgame.
- Phase `84` closed `v2.18` with deterministic credit backtests and one signed
  provider-risk package so external capital review no longer depends on
  ad hoc operator joins over exposure, scorecard, facility, runtime-assurance,
  certification, and recent-loss state.
- Phase `85` introduced signed bond, reserve-lock, and collateral-state
  artifacts over canonical exposure and active-facility truth, with
  fail-closed mixed-currency reserve accounting and explicit `lock`, `hold`,
  `release`, and `impair` posture.
- Phase `87` added immutable bond-loss lifecycle artifacts for delinquency,
  recovery, reserve-release, and write-off state, and derived delinquency
  booking from recent failed-loss evidence instead of a truncated exposure
  page.
- Phase `88` added a non-mutating bonded-execution simulation lane with
  explicit operator control policy, kill-switch semantics, reserve-lock clamp
  options, and fail-closed denial when loss-lifecycle history is truncated or
  delinquency remains unresolved.
- The current planning decision is to sequence ecosystem-legibility work
  before the credit or liability-market ladder so ARC can claim the research
  vision honestly rather than only locally.
- Phase `61` defined ARC's dual-path portable credential boundary:
  `AgentPassport` remains the native source of truth, while
  `arc_agent_passport_sd_jwt_vc` is a projected external credential rooted at
  the same issuer metadata surface with explicit `JWKS` and type metadata.
- Phase `62` closed ARC's first bounded SD-JWT VC profile with explicit
  always-disclosed versus selectively-disclosable claims, holder binding, and
  fail-closed disclosure validation.
- Phase `63` closed portable lifecycle projection by tying issuer metadata,
  portable type metadata, read-only lifecycle distribution, and public resolve
  semantics back to the existing operator lifecycle registry without creating
  a second mutable trust root.
- Phase `64` closed `v2.13` with portable lifecycle qualification evidence,
  dual-path boundary documentation, release-surface updates, and explicit
  milestone audit closure.
- `v2.14` completed the verifier side of the portable credential ladder:
  request-object transport, wallet invocation, public verifier identity, and
  external-wallet qualification now exist over the SD-JWT VC profile added in
  `v2.13`.
- Phases `65` through `68` delivered the narrow `request_uri` plus
  `direct_post.jwt` OID4VP verifier profile, the reference holder adapter,
  trusted-key verifier bootstrap, and the release-boundary closure docs.
- The `v2.14` verifier boundary remains intentionally narrow: no DIDComm, no
  public wallet directory, no synthetic trust registry, and no requirement to
  become a production wallet product.
- `v2.17` completed ARC's governed public certification marketplace surface
  with versioned evidence profiles, public operator metadata, public search
  and transparency, and dispute-aware consumption semantics that keep listing
  visibility separate from runtime trust admission.
- Phases `81` through `92` are now decomposed into executable phase detail so
  the remaining credit, bonded-autonomy, and liability-market ladder can run
  autonomously without another activation step.
- Liability-provider resolution remains curated and fail closed. ARC can only
  resolve an active provider policy when provider id, jurisdiction,
  coverage class, and currency all match one signed published artifact.
- Phase `92` closed the research-completion ladder locally by tying liability
  provider admission, quote/bind, and claim/dispute qualification into one
  bounded marketplace proof and rewriting the public boundary honestly.
- The post-`v2.20` full endgame ladder is now explicit:
  `v2.21` standards-native authorization and credential fabric,
  `v2.22` wallet exchange and sender-constrained authorization,
  `v2.23` common appraisal-result interop,
  `v2.24` verifier federation and cross-issuer portability,
  `v2.25` live capital execution,
  `v2.26` reserve control and claims payment,
  `v2.27` open registry and governance, and
  `v2.28` portable reputation, economics, and endgame qualification.

### Pending Todos

- Execute phase `97` to define the wallet exchange descriptor and
  transport-neutral transaction state.
- Keep the hosted `CI` and `Release Qualification` observation hold in place
  before any external publication of the already locally qualified ARC release
  package.
- Resolve historical milestone archive boundaries before attempting
  phase-directory cleanup.
- Decide whether phase-directory cleanup is safe or should remain deferred.

### Blockers/Concerns

- Several runtime/domain entrypoints are still too large for comfortable
  ownership, especially `trust_control.rs`, `remote_mcp.rs`,
  `arc-mcp-edge/src/runtime.rs`, and `arc-kernel/src/lib.rs`.
- Future interop work must avoid dependency cycles and avoid turning
  `arc-cli` into another transitively giant shell.
- Hosted workflow observation is still outside this local environment, so final
  public release publication cannot be completed from local evidence alone.
- Research-derived future work increases surface area across finance, IAM,
  credential, and runtime-verifier domains; planning must keep those boundaries
  explicit instead of letting them collapse into one vague “trust platform”
  narrative.
- Public-marketplace and liability-network milestones materially increase
  governance and regulatory exposure; docs and runtime behavior must keep ARC
  in a control-plane posture unless the product explicitly chooses otherwise.

## Session Continuity

Last session: 2026-03-29
Stopped at: `v2.20` active locally; phase `92` is the next executable
milestone work
Resume file: None
