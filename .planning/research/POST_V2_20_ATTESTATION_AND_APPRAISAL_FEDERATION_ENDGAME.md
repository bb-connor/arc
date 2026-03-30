# Post-v2.20 Attestation and Appraisal Federation Endgame Plan

**Project:** ARC  
**Scope:** Close the remaining gap between ARC's shipped Azure/AWS/Google appraisal bridge and a vendor-neutral, RATS/EAT-aligned verifier ecosystem  
**Researched:** 2026-03-29  
**Overall confidence:** MEDIUM-HIGH

## Reviewed Inputs

- `docs/research/DEEP_RESEARCH_1.md`
- `docs/WORKLOAD_IDENTITY_RUNBOOK.md`
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
- `docs/release/RELEASE_CANDIDATE.md`
- `spec/PROTOCOL.md`

## Executive Recommendation

ARC should treat the post-`v2.20` attestation/appraisal gap as **four
milestones**, not as one generic "more verifier support" backlog item:

1. **v2.21 Common Appraisal Contract and Claim Vocabulary**
2. **v2.22 External Appraisal Result Interop**
3. **v2.23 Verifier Federation and Trust Bundles**
4. **v2.24 Wider Provider Support and Assurance-Aware Economic Policy**

The key product choice is to keep ARC's current `runtimeAttestation` evidence
surface and signed appraisal export as the operator-facing source of truth,
then layer a stronger common appraisal/result contract, RATS/EAT-aligned
semantics, federated verifier metadata, and additional provider families
around that boundary.

ARC should **not** jump directly from today's bounded Azure/AWS/Google bridge
to "generic attestation interoperability." The correct sequence is:

- first standardize ARC's own common appraisal contract and normalized claim
  vocabulary,
- then make signed appraisal results exchangeable and importable,
- then federate verifier trust, endorsements, and reference values,
- then prove the layer is real by onboarding more providers and binding the
  common assurance model into issuance, credit, bond, and liability policy.

That is the smallest plan that honestly closes the gap called out in the
current docs: ARC already ships a conservative appraisal layer, but it does
not yet ship generic attestation-result interop, verifier federation, or a
vendor-neutral trust layer.

## Current Shipped Boundary

### What ARC already ships

ARC's current shipped boundary is explicit and conservative:

- `runtimeAttestation` is the bounded evidence surface carried with issuance
  and governed requests.
- ARC ships one canonical runtime-attestation appraisal contract that
  separates evidence identity, verifier family, normalized assertions,
  vendor-scoped claims, reason codes, and effective runtime tier.
- ARC ships three concrete verifier bridges:
  - Azure Attestation JWT normalization
  - AWS Nitro attestation document verification
  - Google Confidential VM JWT normalization
- ARC ships explicit `extensions.runtime_assurance.tiers` and
  `extensions.runtime_assurance.trusted_verifiers` policy so stronger runtime
  tiers come from local policy rebinding, not from raw vendor claims alone.
- ARC currently standardizes one typed workload-identity mapping:
  SPIFFE-derived `workloadIdentity`.
- ARC can export one signed runtime-attestation appraisal report through the
  CLI and trust-control HTTP surface.
- Portable trust artifacts may carry normalized `runtimeAttestation`, but the
  portable trust profile still keeps vendor-specific claim meanings opaque.
- Release and standards docs explicitly deny generic attestation-result
  interoperability and deny public or permissionless trust widening.

### What ARC does not yet ship

ARC does **not** yet ship:

- a versioned common appraisal contract that cleanly separates evidence,
  endorsements, reference values, verifier statement, and local relying-party
  decision,
- a standardized claim vocabulary large enough for cross-provider policy,
- import and validation of externally signed appraisal/result artifacts as a
  first-class policy input,
- federated verifier descriptors, trust bundles, or reference-value
  distribution,
- provider-neutral external result transport aligned to a RATS/EAT-style
  verifier ecosystem,
- or assurance-aware economic policy that uses portable appraisal semantics
  across issuance, credit, bond, and liability flows.

## Remaining Gap

The remaining gap after `v2.20` is not "more clouds." It is that ARC's current
appraisal bridge is still an **internal adapter boundary**, not yet a full
vendor-neutral verifier ecosystem.

The concrete missing pieces are:

- ARC's current appraisal contract is stable enough for local export, but it
  is not yet an external ecosystem contract with explicit role separation for
  evidence, endorsements, reference values, verifier output, and relying-party
  decision.
- ARC normalizes only a small bounded assertion set. There is no stable,
  versioned vocabulary for portable claims such as TEE family, measurement
  profile, debug posture, secure boot posture, challenge binding,
  endorsement/reference-value provenance, or freshness class.
- ARC can export signed appraisal reports, but it cannot yet import a signed
  external verifier result and use it under explicit local trust policy.
- `trusted_verifiers` is currently a local operator policy map, not a signed
  federated trust artifact with key rotation, status, supersession, or bundle
  provenance.
- ARC has no distribution plane for verifier keys, endorsement sources, or
  reference values beyond provider-specific code and local policy.
- ARC's provider matrix is still bounded to Azure/AWS/Google. That is enough
  for `v2.15` honesty, but not enough for a vendor-neutral trust claim.
- Issuance, credit, facility, bond, and liability surfaces currently consume a
  narrow runtime-assurance tier plus verifier and evidence digest. They do not
  yet consume a richer portable appraisal model.

## What "Endgame Achieved" Should Mean

ARC can truthfully claim that the attestation/appraisal federation endgame is
achieved only when it can do all of the following without widening trust from
raw foreign evidence:

1. Define one common appraisal/result contract that cleanly separates raw
   evidence, normalized claims, vendor claims, verifier statement,
   endorsement/reference-value provenance, and ARC's own policy decision.
2. Publish one versioned common claim vocabulary and reason taxonomy that more
   than one verifier family can project into.
3. Export and import signed appraisal results over that contract while keeping
   external verifier provenance and local ARC policy decision separate.
4. Federate verifier metadata, keys, endorsements, and reference-value inputs
   through curated trust bundles rather than local ad hoc configuration only.
5. Support additional verifier/provider families, including at least one
   enterprise-operated or third-party verifier lane, on the same common
   contract.
6. Bind that common assurance model into issuance, facility, bond, credit, and
   liability policy so downstream economic flows are no longer hard-coded to
   Azure/AWS/Google semantics.

That is a materially stronger claim than today's bounded bridge, but still
much narrower and safer than "ARC is a universal attestation trust network."

## Architectural Guardrails

The post-`v2.20` design should stay inside these guardrails:

- Keep `runtimeAttestation` as the carried evidence input. Do not force every
  issuance or receipt surface to become a raw EAT or CBOR-first API.
- Treat ARC's signed appraisal/result artifacts as the durable policy boundary.
  Raw external evidence should never bypass verifier and local trust policy.
- Align to RATS/EAT **semantics first**: role separation, claim meaning,
  verifier output, and relying-party policy. Full binary-token parity can stay
  secondary.
- Standardize only claims ARC can defend across providers. Everything else
  stays vendor-scoped.
- Keep federation curated and fail-closed. Public discovery, if added later,
  must remain informational and not auto-admit runtime trust.
- Keep runtime assurance as one strong input into economic decisions, not as a
  universal override that bypasses credit, bond, underwriting, or liability
  controls.

## Recommended Milestone Sequence

### v2.21 Common Appraisal Contract and Claim Vocabulary

**Goal:** Turn ARC's current adapter-facing appraisal shape into a versioned,
vendor-neutral common contract with a stable normalized claim vocabulary.

**Depends on:** `v2.15` through `v2.20`

**Why first:** External interop or verifier federation before common claim
semantics would hard-code vendor translations into every later milestone.

**Recommended requirement IDs:**

- `ATTEST-01`: ARC defines one versioned common appraisal contract that
  separates evidence identity, verifier statement, normalized claims, vendor
  claims, endorsement/reference-value provenance, and local ARC policy
  mapping.
- `ATTEST-02`: ARC defines one versioned normalized claim vocabulary and
  reason-code taxonomy that more than one provider can emit.
- `ATTEST-03`: Runtime-assurance policy can target common appraisal semantics
  instead of only provider-specific rule fields.
- `ATTEST-04`: Existing Azure/AWS/Google bridges remain backward-compatible
  and fail closed during the migration.
- `ATTEST-05`: ARC docs still keep external attestation-result and federation
  claims bounded until later milestones qualify them.

#### Phase 93: Common Appraisal Schema Split and Artifact Inventory

**Depends on:** Phase 92

**Scope**

- Evolve the current appraisal contract into an explicit common schema, with
  separate sections for:
  - evidence identity and digest
  - normalized common claims
  - vendor-scoped claims
  - verifier identity and family
  - endorsement/reference-value provenance
  - verifier outcome and reason codes
  - ARC local policy outcome and effective tier
- Keep `runtimeAttestation` as the carried request surface and map existing
  Azure/AWS/Google adapters into the new common artifact without breaking
  existing export flows.
- Define the proposed artifact set for later milestones:
  - `arc.runtime-attestation.appraisal.v2`
  - `arc.runtime-attestation.claim-profile.v1`
  - `arc.runtime-attestation.result-envelope.v1`
  - `arc.runtime-attestation.verifier-descriptor.v1`
  - `arc.runtime-attestation.trust-bundle.v1`
- Make local ARC policy decision a separate field set from raw verifier
  outcome so imported or replayed results cannot smuggle in a stronger tier.

**Why first**

Today's contract is honest but still optimized for local adapter export.
ARC needs a stricter internal split before it can safely federate or import
external result artifacts.

#### Phase 94: Normalized Claim Vocabulary and Reason Taxonomy

**Depends on:** Phase 93

**Scope**

- Define one portable common claim vocabulary for fields ARC can defend across
  verifier families. The minimum catalog should cover:
  - attester class and TEE family
  - provider/platform identity
  - workload identity binding
  - measurement and image/profile identifiers
  - secure-boot and debug posture
  - freshness and challenge/nonce binding
  - endorsement/reference-value profile identifiers
  - verifier identity and appraisal timestamp
  - normalized assurance posture
- Define one portable reason taxonomy for accept/reject/indeterminate
  appraisal outcomes, including stale evidence, bad signature, unsupported
  format, debug enabled, secure boot missing, measurement mismatch, workload
  mismatch, verifier untrusted, endorsement stale, and policy unmet.
- Preserve provider-specific claims under explicit vendor namespaces instead of
  pretending all claims are portable.
- Version the claim profile so future providers can target the same semantic
  baseline without rewriting old appraisals.

**Recommendation**

Normalize only what ARC can compare coherently across providers. Avoid the
temptation to flatten every vendor claim into fake equivalence.

#### Phase 95: Policy Mapping and Economic Semantics

**Depends on:** Phase 94

**Scope**

- Extend runtime-assurance policy so ARC can target common claim-profile
  fields, normalized reason codes, freshness classes, measurement-profile
  identifiers, and workload-identity constraints.
- Define a stable mapping from common appraisal semantics into ARC economic
  policy inputs:
  - issuance scope ceilings and TTL
  - governed execution step-up or deny paths
  - facility eligibility and reserve posture
  - autonomy and bond prerequisites
  - liability provider evidence requirements
- Keep provider-specific policy escape hatches available, but make them
  explicitly secondary to the common path.
- Define how receipts and signed reports carry common appraisal identifiers so
  later credit and liability artifacts can reference them without re-parsing
  raw vendor evidence.

**Why this matters**

The endgame only matters if the common appraisal model changes real issuance
and economic behavior. Otherwise ARC will still be vendor-specific under the
surface.

#### Phase 96: Compatibility, Qualification, and Boundary Rewrite

**Depends on:** Phase 95

**Scope**

- Add migration and compatibility fixtures proving Azure/AWS/Google adapters
  still emit equivalent policy-visible outcomes through the new common schema.
- Add regression coverage for schema versioning, missing normalized claims,
  conflicting workload identity, and reason-taxonomy downgrade paths.
- Update protocol, standards, runbook, and release-boundary docs so ARC can
  honestly claim a common appraisal contract and claim vocabulary, while still
  denying external interop and federation until later milestones.
- Publish a milestone proof artifact showing one cross-provider policy can be
  evaluated over the normalized claim profile.

#### Milestone Acceptance Criteria

1. ARC defines one versioned common appraisal contract that preserves evidence
   identity, normalized claims, vendor claims, verifier identity, and local
   policy outcome as distinct fields.
2. Azure/AWS/Google adapters project into one shared claim vocabulary and
   reason taxonomy without widening trust.
3. Runtime-assurance policy can target the common vocabulary, not only
   provider family and ad hoc assertion fields.
4. Release docs can truthfully say ARC ships a vendor-neutral internal
   appraisal contract, while still keeping external result interop out of
   scope.

#### Validation / Qualification Expectations

- Golden fixtures for Azure, AWS Nitro, and Google evidence translated into
  the common schema.
- Differential tests proving old versus new appraisal mapping preserves
  effective tier and reject semantics.
- Negative tests for missing claims, malformed workload identity, schema drift,
  and reason-code mismatches.
- One qualification proof showing the same policy outcome across at least two
  providers when the normalized posture is equivalent.

### v2.22 External Appraisal Result Interop

**Goal:** Make ARC able to exchange and consume signed external appraisal
results without trusting raw foreign evidence or collapsing local ARC policy
into foreign verifier semantics.

**Depends on:** `v2.21`

**Why second:** ARC should not federate or import foreign verifier results
before its own common contract and claim vocabulary are stable.

**Recommended requirement IDs:**

- `INTEROP-01`: ARC exports and imports signed appraisal/result envelopes over
  the common contract.
- `INTEROP-02`: Imported appraisals preserve external verifier provenance,
  evidence digest, endorsement/reference-value refs, and original verifier
  outcome separately from ARC local policy outcome.
- `INTEROP-03`: ARC ships one RATS/EAT-aligned external projection over the
  common claim vocabulary.
- `INTEROP-04`: Unsupported or unverifiable external result formats fail
  closed.
- `INTEROP-05`: Receipts and reports distinguish imported appraisal lineage
  from locally produced appraisal lineage.

#### Phase 97: Signed Result Envelope and Provenance Model

**Depends on:** Phase 96

**Scope**

- Define a signed result envelope carrying:
  - common appraisal document
  - verifier descriptor reference
  - signer key id
  - evidence digest and time bounds
  - challenge or nonce binding when present
  - endorsement/reference-value references
  - external verifier outcome
  - ARC import provenance
- Ensure imported result envelopes can be stored and replayed without losing
  the original verifier identity or mutating the local ARC policy record.
- Add explicit source labeling so ARC can always tell the difference between:
  - locally generated appraisal from raw evidence
  - imported third-party appraisal over raw evidence
  - imported transitive appraisal shared by another operator

#### Phase 98: Import Validation, Storage, and Consumption Rules

**Depends on:** Phase 97

**Scope**

- Add CLI and trust-control import flows for signed appraisal/result
  envelopes.
- Validate signature, trusted verifier membership, schema version, freshness,
  workload identity binding, replay safety, and evidence digest integrity
  before the imported result is admitted.
- Keep imported appraisals distinguishable in reporting, analytics, issuance,
  and governed execution so ARC never silently treats foreign evidence as
  native local evidence.
- Allow issuance and governed execution to consume imported appraisals only
  when local policy explicitly permits that origin and verifier class.

**Why this matters**

Export alone is an audit artifact. Import is the step that turns ARC into a
real relying party for external verifier ecosystems.

#### Phase 99: RATS/EAT-Aligned Projection Profile

**Depends on:** Phase 98

**Scope**

- Define one JSON-first ARC compatibility profile over RATS/EAT-style
  semantics for:
  - evidence identity
  - common claims
  - verifier statement
  - relying-party policy result
- Map ARC's common claim vocabulary into that profile so external verifier
  ecosystems have one precise interop target.
- Keep CBOR/CWT or binary-token parity explicitly optional and non-gating for
  this milestone unless a concrete partner demands it.
- Document exactly what ARC means by "RATS/EAT-aligned":
  semantics, roles, and result structure first; not blanket support for every
  external attestation token or every verifier stack.

**Recommendation**

Do not force a protocol-wide binary rewrite just to claim EAT alignment.
Semantic compatibility is the higher-value step.

#### Phase 100: External Interop Qualification and Partner Proof

**Depends on:** Phase 99

**Scope**

- Add end-to-end qualification proving ARC can exchange one signed appraisal
  envelope with an external verifier or partner-side verifier facade.
- Add negative-path coverage for stale results, unknown signer keys,
  mismatched evidence digests, replayed imports, unsupported claim profiles,
  and verifier/origin mismatches.
- Update partner-proof and release docs so ARC can truthfully claim bounded
  external appraisal-result interop.
- Keep public or permissionless verifier discovery out of scope at milestone
  close.

#### Milestone Acceptance Criteria

1. ARC can export and import signed appraisal/result envelopes without losing
   verifier provenance or mutating local policy truth.
2. Imported appraisals cannot elevate `effective_tier` unless local ARC policy
   independently accepts the verifier and claim posture.
3. ARC ships one documented RATS/EAT-aligned projection profile over the
   common appraisal contract.
4. At least one partner or external verifier exchange path qualifies end to
   end.

#### Validation / Qualification Expectations

- Signature and schema validation tests for exported and imported result
  envelopes.
- Replay, freshness, and evidence-digest mismatch regressions.
- One raw HTTP or CLI proof showing external result exchange with ARC.
- Release qualification rows explicitly separating local appraisal generation
  from imported appraisal consumption.

### v2.23 Verifier Federation and Trust Bundles

**Goal:** Move from local `trusted_verifiers` maps to curated verifier
federation with signed metadata, trust bundles, endorsements, and
reference-value distribution.

**Depends on:** `v2.22`

**Why third:** Importing external results safely at scale requires a first
class trust-distribution plane, not only local static configuration.

**Recommended requirement IDs:**

- `FED-01`: ARC defines signed verifier-descriptor artifacts with identity,
  family, key material, supported evidence types, supported claim profile, and
  lifecycle state.
- `FED-02`: ARC defines signed trust bundles that package verifier
  descriptors, allowed claim profiles, and trust status.
- `FED-03`: ARC defines a distribution model for endorsement and
  reference-value inputs that is auditable, revocable, and separate from raw
  runtime admission.
- `FED-04`: ARC can import curated federation bundles without claiming a
  permissionless global trust network.
- `FED-05`: Trust-control exposes bundle health, stale inputs, and revocation
  or supersession state as first-class operator diagnostics.

#### Phase 101: Verifier Descriptor and Trust Bundle Artifacts

**Depends on:** Phase 100

**Scope**

- Define `verifier-descriptor` artifacts that publish:
  - verifier identity and family
  - signing keys or key references
  - supported evidence classes
  - supported claim profile versions
  - supported endorsement/reference-value sources
  - lifecycle state and supersession pointers
- Define signed trust bundles that group approved verifier descriptors and key
  sets for one operator or one curated federation.
- Map today's local `trusted_verifiers` configuration into the new trust-bundle
  model without widening the runtime trust boundary.

#### Phase 102: Endorsement and Reference-Value Distribution

**Depends on:** Phase 101

**Scope**

- Define first-class artifacts for endorsement and reference-value inputs so
  ARC can decouple provider-specific code from trusted measurement data.
- Require imported reference values and endorsement sources to carry explicit
  issuer, lifecycle, cache, and supersession metadata.
- Bind reference-value profile identifiers into the common appraisal claim
  vocabulary so policy can target them portably.
- Keep local operator admission explicit: imported reference values and
  endorsements inform trust, but they do not auto-authorize runtime requests.

**Why this matters**

Without a reference-value plane, ARC remains stuck on hard-coded vendor logic
even if result envelopes become importable.

#### Phase 103: Federation Workflows and Policy Distribution

**Depends on:** Phase 102

**Scope**

- Extend ARC federation surfaces so operators can publish, import, approve,
  supersede, and revoke verifier trust bundles and related artifacts.
- Keep federation bilateral or curated-network based. Discovery, if exposed,
  stays informational and never auto-admits runtime trust.
- Add explicit policy distribution for:
  - allowed verifier classes
  - allowed claim profiles
  - imported appraisal origins
  - endorsement/reference-value source admission
- Expose bundle and descriptor state through trust-control reports and health
  surfaces.

#### Phase 104: Federation Qualification and Boundary Rewrite

**Depends on:** Phase 103

**Scope**

- Add regression coverage for stale bundles, revoked keys, superseded
  descriptors, disputed endorsement inputs, and conflicting bundle versions.
- Add operator qualification fixtures showing that runtime admission fails
  closed when federation inputs drift or go stale.
- Update protocol and standards docs so ARC can truthfully claim curated
  verifier federation and trust-bundle distribution.
- Keep permissionless public trust registries and automatic runtime trust
  admission explicitly out of scope.

#### Milestone Acceptance Criteria

1. ARC can import and evaluate signed verifier trust bundles instead of relying
   only on local static `trusted_verifiers` configuration.
2. Verifier descriptors, endorsement sources, and reference values are
   separate auditable artifacts with lifecycle and supersession semantics.
3. Federation inputs affect runtime trust only through explicit local policy
   admission.
4. Trust-control surfaces expose stale, revoked, superseded, and disputed
   federation state clearly enough for operators to fail closed intentionally.

#### Validation / Qualification Expectations

- Bundle-signature, key-rotation, and supersession regressions.
- Negative tests for stale reference values, conflicting bundle versions,
  revoked verifiers, and unsupported claim profiles.
- One partner or multi-operator proof showing bundle publication and bundle
  import without widening runtime trust from discovery alone.
- Updated runbook guidance for verifier-bundle recovery and incident response.

### v2.24 Wider Provider Support and Assurance-Aware Economic Policy

**Goal:** Prove the vendor-neutral layer is real by onboarding more provider
families and binding the common appraisal model directly into issuance,
facility, bond, and liability policy.

**Depends on:** `v2.23`

**Why last:** Provider expansion and policy activation are only worth doing
after the common contract, import model, and federation plane are stable.

**Recommended requirement IDs:**

- `POL-01`: ARC supports at least two additional verifier/provider families on
  the common appraisal contract.
- `POL-02`: ARC supports at least one enterprise-operated or third-party
  verifier lane that is not just Azure/AWS/Google raw evidence normalization.
- `POL-03`: Issuance, credit, bond, and liability policy can target common
  appraisal semantics and provenance, not only provider-specific fields.
- `POL-04`: Provider-facing risk and liability artifacts carry vendor-neutral
  appraisal references and reason codes.
- `POL-05`: ARC can update its public boundary to claim a bounded
  vendor-neutral verifier ecosystem and trust layer.

#### Phase 105: Provider-Abstraction Refactor and Generic Adapter Interface

**Depends on:** Phase 104

**Scope**

- Refactor verifier adapters so Azure/AWS/Google are simply concrete
  implementations of one generic common-appraisal interface.
- Separate provider family, evidence format, TEE family, and verifier origin
  as distinct concepts in the adapter contract.
- Make imported third-party results and local raw-evidence adapters converge on
  the same common result-envelope path.
- Keep backward-compatible report and receipt surfaces for existing operators.

#### Phase 106: Additional Provider Families and Enterprise Verifier Lane

**Depends on:** Phase 105

**Scope**

- Add at least two additional provider or verifier families. Recommended
  priority order:
  - direct AMD SEV-SNP family
  - direct Intel TDX family
  - one enterprise-operated or third-party verifier facade over the common
    result-envelope contract
- Require every new family to emit the same common claim profile, reason
  taxonomy, and verifier-provenance fields as the existing bridges.
- Keep non-SPIFFE workload identity typed support out of scope unless ARC can
  define a defensible cross-provider mapping.

**Recommendation**

The proof point is not "support every cloud." The proof point is "support more
than one new family without changing the policy language."

#### Phase 107: Issuance, Credit, Bond, and Liability Policy Activation

**Depends on:** Phase 106

**Scope**

- Extend issuance policy so capability TTL, scope ceilings, and minimum
  runtime-assurance requirements can target:
  - claim profile version
  - verifier class or origin
  - freshness class
  - reference-value posture
  - normalized debug and secure-boot posture
- Extend credit, facility, and bond policy so scorecards and facility
  decisions can use portable appraisal semantics instead of cloud-specific
  rule branches.
- Extend provider-risk-package, quote, coverage, claim, and dispute artifacts
  so liability policy can require portable appraisal classes and evidence
  references without encoding Azure/AWS/Google-only assumptions.
- Ensure receipts, scorecards, provider-risk packages, coverage artifacts, and
  claim packages carry stable appraisal identifiers and normalized reason
  references for auditability.

**Why this matters**

If only the attestation subsystem understands the normalized model, ARC has
not actually achieved a vendor-neutral trust layer. The economic surfaces must
consume it too.

#### Phase 108: End-to-End Qualification, Partner Proof, and Boundary Closeout

**Depends on:** Phase 107

**Scope**

- Add end-to-end qualification over:
  - locally generated appraisals
  - imported external appraisals
  - federated trust bundles
  - at least two additional provider families
  - assurance-aware issuance and economic policy flows
- Produce partner-proof artifacts showing:
  - one external verifier exchange
  - one vendor-neutral provider-risk package
  - one liability evidence package with portable appraisal references
- Update release, standards, and protocol docs so ARC can truthfully claim the
  bounded verifier-federation endgame is achieved.
- Keep explicit non-goals and trust-boundary caveats in the final boundary
  update.

#### Milestone Acceptance Criteria

1. ARC supports at least two additional provider/verifier families plus one
   enterprise-operated or third-party verifier lane on the same common
   contract.
2. Issuance, scorecard/facility, bond, and liability surfaces consume portable
   appraisal semantics and provenance.
3. Provider-facing economic artifacts can express attestation requirements in a
   vendor-neutral way.
4. ARC can update public boundary docs to claim a bounded vendor-neutral
   verifier ecosystem with curated federation and external result interop.

#### Validation / Qualification Expectations

- Multi-provider regression corpus proving common-policy evaluation across
  local and imported appraisal results.
- Negative tests for stale bundles, stale appraisal imports, missing reference
  values, workload-identity mismatch, unsupported provider families, and
  improper policy widening.
- One credit or facility proof showing assurance posture affects bounded
  capital policy.
- One liability proof showing portable appraisal semantics flow through
  provider-risk, quote, coverage, and claim evidence.

## Cross-Milestone Validation and Qualification Expectations

The full ladder should not be treated as complete unless ARC adds:

- common-schema golden fixtures for every supported provider family,
- import/export qualification for signed appraisal/result envelopes,
- trust-bundle and verifier-descriptor lifecycle tests,
- stale or revoked endorsement/reference-value tests,
- cross-provider policy equivalence tests over the normalized claim profile,
- release-proof and partner-proof artifacts separating local and imported
  appraisal provenance,
- and doc updates that keep support claims bounded at each milestone instead
  of jumping directly to "universal verifier interoperability."

The release and qualification corpus should also prove these fail-closed
properties:

- imported results do not elevate runtime tier without explicit local policy,
- stale or superseded verifier bundles deny rather than silently degrade,
- unknown claim-profile versions deny rather than silently map,
- workload identity conflicts still fail closed,
- vendor-scoped claims do not bypass normalized policy checks,
- and liability or credit flows do not widen solely because runtime assurance
  is present.

## Explicit Non-Goals

The post-`v2.20` plan should still exclude:

- a permissionless public verifier marketplace or auto-trusting global trust
  registry,
- automatic trust in arbitrary external EAT or attestation-result tokens,
- standardization of every vendor-specific TEE claim,
- typed non-SPIFFE workload identity standardization in this cycle,
- universal wallet- or browser-grade attestation portability claims,
- automatic underwriting, credit, or liability decisions based only on TEE
  presence,
- consensus trust replication or cross-region federation guarantees from this
  work alone,
- and blanket claims of equivalence across all TEEs, verifiers, or cloud
  providers.

## Trust-Boundary Caveats

- ARC remains the relying party for issuance and economic policy. Imported
  verifier outputs are evidence inputs, not authority by themselves.
- Curated federation is still a local trust decision. Discovery can inform,
  but it must not auto-admit runtime trust.
- A valid attestation or high-assurance TEE does not prove benign intent,
  low-loss behavior, or insurability. It is one strong signal among several.
- Reference values and endorsements reduce ambiguity, but they do not remove
  the need for explicit local policy and operator review.
- Runtime assurance should continue to gate ceilings, autonomy, and provider
  evidence posture. It should not become a hidden override that bypasses
  receipts, settlements, underwriting, facility, bond, or liability controls.
- ARC should only claim RATS/EAT alignment to the extent it has a documented
  compatibility profile, qualification evidence, and bounded support statement.

## Resulting Milestone Ladder

1. **v2.21 Common Appraisal Contract and Claim Vocabulary**  
   Phases `93` through `96`
2. **v2.22 External Appraisal Result Interop**  
   Phases `97` through `100`
3. **v2.23 Verifier Federation and Trust Bundles**  
   Phases `101` through `104`
4. **v2.24 Wider Provider Support and Assurance-Aware Economic Policy**  
   Phases `105` through `108`

This is the recommended post-`v2.20` ladder if ARC wants to move from today's
bounded multi-cloud appraisal bridge to a fuller verifier ecosystem and
vendor-neutral trust layer without widening its public claims faster than the
implementation can justify.
