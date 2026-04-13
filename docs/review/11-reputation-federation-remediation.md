# Reputation, Passport, Federation, and Sybil-Resistance Remediation

## Problem

ARC currently has credible building blocks for local reputation scoring,
passport packaging, and bounded bilateral evidence portability, but it does
not yet have the identity, issuer-independence, aggregation, or network
governance machinery needed to make stronger portable-trust claims literally
true.

Today the repo is honest in several narrow places:

- local reputation is computed from one operator's local receipts, lineage, and
  budget data (`crates/arc-reputation/src/score.rs:3-45`)
- imported trust is conservative, attenuated, and explicitly kept separate from
  local truth (`docs/IDENTITY_FEDERATION_GUIDE.md:127-180`)
- multi-issuer passports are presentation bundles, not a synthesized
  cross-issuer score (`docs/AGENT_PASSPORT_GUIDE.md:288-343`)
- federation imports remain visibility-only until explicit local activation
  (`crates/arc-federation/src/lib.rs:114-136`, `974-1003`)

The problem is that the broader narrative around portable trust, reputation,
passports, federation, and Sybil resistance often reads as if ARC already has
an interoperable multi-issuer reputation network. It does not. It has local
truth plus bounded portability scaffolding.

## Current Evidence

- **Local reputation is real and deterministic.**
  `compute_local_scorecard` builds a score from local receipts, local
  capability-lineage records, and local budget usage for one `subject_key`
  (`crates/arc-reputation/src/score.rs:3-45`). The corpus model is local by
  construction: receipts, capabilities, budgets, and optional incidents
  (`crates/arc-reputation/src/model.rs:226-272`).

- **Imported trust is explicitly segregated from local truth.**
  The docs say imported evidence does not rewrite the local receipt log, local
  budget history, or native scorecard (`docs/IDENTITY_FEDERATION_GUIDE.md:140-180`,
  `docs/AGENT_PASSPORT_GUIDE.md:428-441`). The imported-signal model is also
  narrow: provenance is mostly strings plus timestamps and counts, and policy is
  just attenuation, proof requirement, max age, and issuer allowlist
  (`crates/arc-reputation/src/model.rs:228-272`). The scorer then computes a
  `LocalReputationScorecard` and optionally attenuates its composite score
  (`crates/arc-reputation/src/compare.rs:242-292`).

- **Passport multi-issuer support is intentionally conservative.**
  The guide says no cross-issuer aggregate score is invented, policy evaluation
  runs per credential, and a passport is accepted if at least one credential
  satisfies the policy (`docs/AGENT_PASSPORT_GUIDE.md:295-343`). Cross-issuer
  portfolios likewise preserve per-entry provenance; visibility does not imply
  local admission; local activation requires an explicit signed trust pack; and
  subject rebinding requires an explicit signed migration artifact
  (`docs/AGENT_PASSPORT_GUIDE.md:308-325`).

- **Public identity is still `did:arc`-anchored and compatibility-bounded.**
  The guide says broader DID methods are compatibility inputs while `did:arc`
  remains the signed provenance anchor (`docs/AGENT_PASSPORT_GUIDE.md:80-91`).
  The public identity contracts enforce that `did:arc` remains present for
  subject and issuer support and require ARC-native passport compatibility plus
  ARC-controlled basis references (`crates/arc-core/src/identity_network.rs:50-112`,
  `315-366`). The public profile document also explicitly rejects universal
  trust across arbitrary DID methods (`docs/standards/ARC_PUBLIC_IDENTITY_PROFILE.md:14-48`).

- **Federation already encodes conservative local-vs-global boundaries.**
  Federation import control requires explicit local activation, manual review,
  stale-input rejection, visibility without runtime trust, and prohibition of
  ambient runtime admission (`crates/arc-federation/src/lib.rs:122-136`,
  `974-1003`). The federation profile also says shared reputation clearing is
  not a universal oracle (`docs/standards/ARC_FEDERATION_PROFILE.md:15-52`).

- **There is real contract-level groundwork for cross-issuer clearing.**
  `FederatedReputationClearingArtifact` already models participating operators,
  local weighting, input references, Sybil controls, accepted/rejected inputs,
  and an effective admission class (`crates/arc-federation/src/lib.rs:265-322`).
  Validation enforces per-issuer caps, minimum distinct issuers, local weighting
  requirements, and corroboration for blocking negative events
  (`crates/arc-federation/src/lib.rs:707-820`, `1067-1146`).

- **The repo itself still describes the true network layer as future work.**
  The reputation doc places cross-organizational aggregation, Sybil detection,
  and an aggregator service in Phase 3 (`docs/AGENT_REPUTATION.md:1108-1129`).
  The passport guide also says important identity/network pieces are not yet
  shipped, including `did:arc` issuance/resolution, `did:arc:update`, and
  permissionless discovery networks (`docs/AGENT_PASSPORT_GUIDE.md:734-746`).

## Why Claims Overreach

- **Issuer independence is not operationalized.**
  Imported trust currently knows an `issuer` string, `partner`, and signer key,
  but not a first-class issuer descriptor with ownership, trust-root lineage,
  correlation group, audit state, or economic accountability
  (`crates/arc-reputation/src/model.rs:228-272`). An allowlist of issuer
  strings is not an independence model (`crates/arc-reputation/src/compare.rs:254-279`).

- **Sybil resistance is still more thesis than mechanism.**
  The reputation doc says identity is capability-gated and Sybils are
  detectable from delegation-graph patterns (`docs/AGENT_REPUTATION.md:648-664`),
  but the shipped scorer is single-subject local scoring, not cross-identity
  clustering (`crates/arc-reputation/src/score.rs:3-45`). Worse, the incident
  correlation path explicitly ignores `subject_key`
  (`crates/arc-reputation/src/compare.rs:209-238`). There is no portable
  identity cost model, no issuer-bounded minting model, and no network-level
  anti-Sybil enforcement path.

- **Passport semantics stop well short of portable trust semantics.**
  Multi-issuer support is `any_of` evaluation over independently verified
  credentials, not a network-qualified aggregate (`docs/AGENT_PASSPORT_GUIDE.md:295-343`).
  Cross-issuer portfolios preserve visibility and provenance, but they do not
  produce a portable score or admission class on their own
  (`docs/AGENT_PASSPORT_GUIDE.md:308-325`).

- **Portability today is artifact portability, not trust portability.**
  Imported trust is intentionally kept separate from local truth and merely
  surfaced as an attenuated signal (`docs/IDENTITY_FEDERATION_GUIDE.md:140-180`,
  `docs/AGENT_PASSPORT_GUIDE.md:428-441`). That is the right current design,
  but it means ARC cannot yet claim that reputation itself is portable in the
  strong sense.

- **The identity layer is still ARC-private at the trust anchor.**
  Broader DID methods are compatibility inputs, while `did:arc` remains the
  provenance anchor and required method in the public identity profile
  (`docs/AGENT_PASSPORT_GUIDE.md:80-91`,
  `crates/arc-core/src/identity_network.rs:315-366`,
  `docs/standards/ARC_PUBLIC_IDENTITY_PROFILE.md:14-48`). That is a bounded
  interop profile, not a neutral identity network.

- **Federation is not yet a general-purpose trust network.**
  The federation contracts are explicit that imported evidence stays visibility-
  only until local activation and manual review (`crates/arc-federation/src/lib.rs:122-136`,
  `974-1003`). That is honest bilateral portability. It is not yet portable
  trust with automatic cross-operator semantics.

- **The strongest honest claim today is narrower.**
  Before a real network exists, ARC can honestly claim:
  - deterministic local reputation scoring per operator
  - signed reputation/passport artifacts with multi-issuer presentation
  - conservative imported trust reporting with attenuation and fail-closed
    guardrails
  - bilateral/manual federation activation with explicit local review

  It cannot honestly claim:
  - a universal portable reputation score
  - issuer-independent cross-operator trust
  - a Sybil-resistant public reputation network
  - broad federation-based admission beyond local policy

## Target End-State

ARC should target a five-layer model and name each layer precisely.

- **Layer 1: Local Truth.**
  One operator computes one local reputation scorecard from its own receipts,
  lineage, incidents, and budgets. This remains authoritative only inside that
  operator's domain.

- **Layer 2: Portable Attestation.**
  An operator can sign a portable reputation summary or negative-event artifact
  about a subject, with methodology, time window, evidence references, and
  lifecycle state.

- **Layer 3: Identity Continuity.**
  Multiple issuers can only be aggregated when subject continuity is proven by
  a first-class continuity artifact, not by matching display claims or hand-set
  migration metadata.

- **Layer 4: Network Clearing.**
  A separate clearing process can combine multiple portable issuer artifacts
  into a network-qualified trust view only when:
  - issuers satisfy an independence policy
  - subject continuity is proven
  - methodologies are compatible
  - freshness and revocation checks pass
  - local weighting and oracle caps are enforced

- **Layer 5: Local Admission.**
  Every relying party and operator still makes its own admission decision from
  local policy, local truth, and optionally network-cleared portable trust.

If ARC reaches that architecture, it can honestly claim:

- portable reputation attestations
- bounded, independence-aware cross-issuer clearing
- passport-backed presentation of local and network-qualified trust claims
- qualified federation across operators with explicit portability boundaries
- Sybil resistance in the precise sense of "costed, bounded, independence-aware
  resistance," not "impossible to game"

## Required Identity/Reputation/Federation Changes

### 1. Split local, portable, and network trust into distinct artifact families

The current design needs a hard type split:

- `LocalReputationScorecard`
  Current operator-local truth.
- `PortableReputationSummary`
  Signed by one issuer about one subject for one time window and one scoring
  methodology version.
- `PortableNegativeEvent`
  Signed, reviewable, time-bounded adverse evidence with severity and dispute
  status.
- `NetworkReputationClearing`
  Produced only after multi-issuer continuity, independence, freshness, and
  weighting checks pass.
- `FederatedAdmissionDecision`
  Produced by a local relying party or operator after applying local policy to
  local truth plus optional network-cleared evidence.

Imported trust must stop looking like "recompute a local scorecard over an
imported corpus, then attenuate it." That is useful as an operator debugging
surface, but it is not portable trust. Keep it as a compatibility path, but add
real portable artifact verification and distinct network-cleared output.

### 2. Make issuer identity and issuer independence first-class

Introduce a signed issuer/operator descriptor that includes:

- stable `operator_id`
- stable `issuer_id`
- trust-root fingerprints and signer-set lifecycle
- governance / common-control metadata
- certification or review state
- jurisdiction / policy domain
- correlation-group identifiers for shared control
- revocation / suspension state

Then define an `IssuerIndependencePolicy` for clearing and admission:

- multiple signers from one operator count as one issuer
- multiple operators in one correlation group count as one independence group
- issuers without explicit descriptor metadata cannot contribute to
  network-level clearing
- policies can require minimum independent groups, not just minimum issuer
  strings

The existing `minimum_independent_issuers`, `maximum_inputs_per_issuer`, and
`oracle_cap_bps` controls in `FederatedSybilControl`
(`crates/arc-federation/src/lib.rs:281-299`, `707-820`) are the right seed, but
they need real issuer-descriptor plumbing rather than free-form operator names.

### 3. Add a real subject-continuity and subject-migration layer

ARC needs an explicit continuity model that separates:

- local subject key
- portable subject identifier
- enterprise/provider-bound identity
- migrated / rotated subject lineage

Add a signed `PortableSubjectContinuityArtifact` with at least:

- prior subject binding
- new subject binding
- continuity reason: key rotation, enterprise rebind, migration, merger
- holder proof of possession
- issuer signatures or verifier signatures establishing the continuity
- issuance / expiry windows
- revocation state

Cross-issuer aggregation must fail closed unless all contributing portable
reputation artifacts point to the same portable subject identity or are bridged
by accepted continuity artifacts. The current portfolio language about explicit
migration artifacts is directionally correct (`docs/AGENT_PASSPORT_GUIDE.md:313-325`);
it now needs to become an operational prerequisite for clearing and admission.

### 4. Define a real Sybil cost model

The project needs to stop treating graph analysis alone as Sybil resistance.
Graph analysis is a detector, not a cost model.

Add identity assurance classes such as:

- `self_asserted`
- `enterprise_bound`
- `attested_workload_bound`
- `bonded_operator_bound`
- `certified_human_reviewed`

Each class should define:

- issuance prerequisites
- revocation rules
- portable weight ceiling
- whether it may contribute to network clearing
- whether it may originate blocking negative events
- required proof material

Then add explicit Sybil-cost controls:

- per-issuer subject issuance quotas
- rate limits on new identities
- optional stake / bond / slashable collateral for issuers or subjects
- churn penalties for subjects that rotate too frequently without a continuity
  artifact
- dependence caps so one operator cannot dominate the clearing output

With that in place, "Sybil-resistant" can mean:
"portable trust requires identities and issuers with nontrivial issuance cost,
bounded influence, and auditable continuity."

Without that, the honest term is only "Sybil-aware" or "Sybil-detecting."

### 5. Upgrade portable reputation and negative-event artifacts

Define one portable reputation summary schema with:

- issuer / operator descriptor refs
- subject continuity ref
- scoring methodology ID and version
- measurement window
- confidence / uncertainty metadata
- corpus size and diversity metadata
- evidence coverage metadata
- receipt / checkpoint / proof references
- assurance class of the subject
- revocation / expiry / lifecycle state

Define one portable negative-event schema with:

- event taxonomy and severity
- evidence references
- subject continuity ref
- issuer / operator descriptor ref
- dispute state
- appeal state
- expiry / stale policy
- whether the event is blocking or advisory

The current imported-trust provenance record is far too weak for this
(`crates/arc-reputation/src/model.rs:228-272`). It is good enough for
conservative operator visibility, not for portable market-wide trust.

### 6. Turn shared reputation clearing from a contract into a service boundary

The repo already has the contract. Now it needs an operational lane.

Implement a `reputation clearing` service that:

- ingests signed portable summaries and negative events
- resolves subject continuity
- resolves issuer descriptors and independence groups
- rejects stale, revoked, or incompatible artifacts
- enforces `minimum_independent_issuers`
- collapses correlated issuers into one influence bucket
- enforces `maximum_inputs_per_issuer`
- enforces `oracle_cap_bps`
- requires corroboration for blocking negative events
- produces a signed `NetworkReputationClearing` artifact with:
  - accepted inputs
  - rejected inputs
  - effective admission class
  - network score or confidence band
  - rationale

The clearing algorithm should be robust by default:

- weighted median or trimmed mean, not naive average
- explicit confidence intervals
- explicit "insufficient independent evidence" state
- explicit downgrade when only low-assurance identities contribute

### 7. Rebuild passport semantics around claim modes

Keep the current passport as the presentation bundle, but add claim modes so
verifiers can tell what kind of trust statement they are looking at:

- `bundle_only`
  Raw independently signed credentials; no aggregation.
- `any_of`
  Current verifier mode.
- `quorum`
  Requires multiple independent issuers.
- `network_cleared`
  Requires a signed clearing artifact.
- `local_admission_ready`
  Requires a local operator's explicit admission artifact.

Passports should not silently blur these modes together. Add explicit policy
flags so relying parties can require:

- issuer independence thresholds
- subject continuity proof
- minimum assurance classes
- active lifecycle on each credential
- active lifecycle on the clearing artifact
- corroboration requirements for adverse evidence

### 8. Make federation levels explicit

The federation layer should be described as four levels:

- `visibility`
  Imported evidence is visible only.
- `qualified_import`
  Imported portable artifacts are verified and locally attenuated, but not
  admitted automatically.
- `network_clearing`
  Independent issuers are cleared into a network-qualified artifact.
- `admission_federation`
  A local operator may auto-admit some classes of cleared artifacts under an
  explicit federation policy.

Current ARC behavior is almost entirely `visibility` plus narrow
`qualified_import`. The docs should say that plainly until the higher levels
exist.

For `admission_federation`, require:

- explicit partner / issuer contracts
- explicit subject continuity methods
- dispute-handling rules
- lifecycle / revocation propagation
- local opt-in
- automatic fallback to visibility-only on stale or contradictory inputs

### 9. Keep local and global trust semantically separate

This separation is crucial and should remain true even after the network exists.

- local scorecards must remain local truth
- imported portable summaries must never mutate local history
- network clearing must remain a derived external layer
- local admission remains a relying-party decision

That is how ARC avoids turning "portable trust" into "ambient trust."

### 10. Add claim-discipline gates

Release documentation should be gated by qualification states:

- do not claim "portable trust" unless network-cleared artifacts ship
- do not claim "Sybil-resistant" unless assurance classes, issuer independence,
  and clearing enforcement ship
- do not claim "public identity network" unless subject continuity and issuer
  descriptors are operational
- do not claim "federated trust" beyond bilateral/manual import unless the
  corresponding federation level is qualified

## Validation Plan

- **Identity continuity tests**
  - same subject across two independent issuers via direct same-key continuity
  - key rotation continuity
  - enterprise-principal rebinding continuity
  - invalid or contradictory continuity artifacts fail closed

- **Issuer independence tests**
  - two signers under one operator count as one influence bucket
  - two operators in one correlation group count as one influence bucket
  - missing issuer descriptor prevents network clearing
  - revoked issuer descriptor invalidates affected clearing outputs

- **Aggregation tests**
  - `any_of` passport evaluation remains available for bounded compatibility
  - `quorum` mode requires configured independent-issuer threshold
  - `network_cleared` mode rejects incompatible scoring methodologies
  - conflicting positive and negative inputs yield deterministic, explainable
    outcomes

- **Sybil adversarial simulations**
  - one operator minting many fresh identities cannot dominate network score
  - rapid identity churn degrades trust unless continuity proofs exist
  - low-cost identity classes receive bounded or zero network weight
  - graph-based detectors produce alerts without becoming the only control

- **Federation tests**
  - visibility-only imports do not affect runtime admission
  - qualified imports remain attenuated and auditable
  - admission federation works only when explicit policy, continuity, lifecycle,
    and issuer-independence checks all pass
  - stale or contradictory imports fall back to visibility-only

- **Negative-event tests**
  - blocking negative events require corroboration by policy
  - dispute / appeal state downgrades or suspends blocking behavior
  - expired negative events stop affecting network clearing

- **Docs / release-gate tests**
  - generated docs state the correct federation level
  - generated docs state whether portable trust is bundle-only, cleared, or
    admission-qualified
  - no badge or claim upgrades without qualification artifacts

## Milestones

### M0. Claim Reset

- Narrow docs to today's truthful surface:
  - local reputation
  - multi-issuer bundle verification
  - conservative imported trust
  - visibility-first federation
- Add claim taxonomy to README, passport docs, and federation docs

### M1. Identity and Issuer Foundations

- ship issuer/operator descriptor artifacts
- ship subject continuity artifact and verifier
- add lifecycle and revocation for issuer descriptors and continuity artifacts

### M2. Portable Artifact Upgrade

- ship `PortableReputationSummary` and `PortableNegativeEvent`
- wire imported-trust paths to verify those artifacts directly
- keep legacy attenuated-import reporting as a compatibility/debug lane

### M3. Network Clearing

- implement clearing service
- operationalize `FederatedReputationClearingArtifact`
- add issuer-independence resolution and robust aggregation
- emit signed clearing artifacts

### M4. Passport and Policy Modes

- add passport claim modes
- add verifier policy requirements for continuity, independence, and clearing
- add lifecycle enforcement for clearing artifacts

### M5. Federation Admission

- implement qualified import and admission-federation policies
- add fallback-to-visibility semantics
- add dispute / appeal handling for negative events

### M6. Sybil Qualification and Release Upgrade

- run adversarial simulations
- run multi-operator qualification
- only then upgrade documentation to stronger portable-trust and
  Sybil-resistance language

## Acceptance Criteria

- ARC can produce a signed local reputation scorecard, a signed portable
  summary, and a signed network-clearing artifact as three distinct artifacts.
- Imported trust is no longer just an attenuated local scorecard replay; it can
  verify and ingest first-class portable summaries and negative events.
- Cross-issuer aggregation fails closed unless subject continuity is proven.
- Cross-issuer aggregation fails closed unless issuer independence thresholds
  are satisfied.
- Multiple signers or operators under common control cannot inflate the
  effective issuer count.
- Blocking negative events require the configured corroboration rule.
- Passport policies can distinguish bundle-only, quorum, network-cleared, and
  local-admission-ready trust modes.
- Federation imports remain non-ambient by default and only widen to admission
  under explicit qualified policy.
- Documentation can state, precisely and testably, whether ARC ships:
  - local reputation
  - portable reputation artifacts
  - network clearing
  - federated admission
  - costed Sybil resistance

## Risks/Non-Goals

- **Perfect Sybil prevention is not realistic.**
  The achievable goal is costed, bounded, auditable Sybil resistance, not
  impossibility.

- **Permissionless ambient trust is not a goal.**
  Even after the network exists, local admission should remain explicit and
  fail closed.

- **Portable trust should not rewrite local truth.**
  Keeping those planes separate is a feature, not a weakness.

- **A real network requires real operators.**
  Unit tests and local fixtures can qualify the protocol, but strong claims
  about portability and network effects still depend on multi-operator
  deployment.

- **Privacy and regulation will constrain design choices.**
  Subject continuity, issuer descriptors, and negative-event portability need
  careful privacy, retention, and dispute-handling design.

- **Non-goal: universal identity interoperability on day one.**
  It is acceptable for ARC to remain `did:arc`-anchored until broader DID
  method support is actually verified, not just named in schemas.
