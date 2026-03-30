# Phase 54: Credential Status, Revocation, and Distribution Contracts - Research

**Researched:** 2026-03-27
**Domain:** Portable credential lifecycle over ARC passport + OID4VCI issuance
**Confidence:** HIGH

<phase_alignment>
## Phase Alignment

The phase-54 executable plan files are not yet present in this directory, so
this memo is aligned conservatively to:

- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`
- the current passport lifecycle implementation
- the newly added phase-53 OID4VCI-compatible issuance surfaces

The analysis below assumes phase 54 must make lifecycle semantics portable
without changing ARC's trust root, artifact format, or operator-bounded
deployment model.
</phase_alignment>

<user_constraints>
## Locked Constraints

### Trust boundary

- Preserve the current ARC-native trust model:
  - `did:arc` issuer and subject identifiers remain the credential truth
  - Ed25519-signed ARC passport credentials remain the signed credential truth
  - HTTPS transport identifiers remain transport identifiers, not new trust
    roots
- Do not widen trust into:
  - a public portability marketplace
  - a public wallet network
  - a synthetic global trust registry
  - automatic federation or discovery that widens operator authority

### Phase scope

- Build on current passport lifecycle truth plus the new OID4VCI-compatible
  issuance lane from phase 53.
- Cover status, revocation, supersession, and distribution contracts only.
- Do not pull wallet/holder presentation transport into this phase. That
  remains phase 55.
- Do not try to prove external wallet or verifier compatibility in this phase.
  That remains phase 56.

### Safety and semantics

- Supersession and revocation must remain explicit mutable lifecycle state
  layered beside immutable signed passport artifacts.
- Missing, stale, or contradictory lifecycle state must fail closed.
- Portable distribution should be an interoperability layer over existing ARC
  truth, not a second mutable truth store.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| VC-02 | Credential status, revocation, and supersession semantics are portable to wallet and verifier ecosystems without weakening current trust boundaries. | Reuse the existing lifecycle record and resolve model as the authoritative state, then add a small portable status-reference layer to the OID4VCI issuance profile and trust-control distribution surfaces. |
| VC-05 | Broader credential interop preserves ARC's conservative rules against synthetic global trust, silent federation, and authority widening. | Keep lifecycle truth operator-owned and transport-discovered, do not introduce global status lists or public registries, and keep delivered credentials as ARC passports rather than rewriting them into broader VC profiles. |
</phase_requirements>

## Summary

ARC already has truthful lifecycle state for passports:

- typed lifecycle state and distribution fields in `arc-credentials`
- durable local publication, supersession, resolution, and revocation logic in
  `arc-cli`
- remote trust-control lifecycle routes
- DID service discovery support for passport status resolution

Phase 53 added a conservative OID4VCI-compatible issuance lane, but it did not
yet connect issued credentials to portable lifecycle discovery and status
evaluation. That is the actual phase-54 gap.

The conservative phase-54 recommendation is:

1. keep `PassportStatusRegistry` plus `PassportLifecycleResolution` as the
   source of truth
2. formalize one portable status-reference contract that points external
   consumers at that truth
3. advertise lifecycle support through the ARC OID4VCI profile and the issued
   credential delivery surface
4. require explicit operator publication or an equivalent configured
   distribution source before an issued credential can claim portable lifecycle
   support
5. fail closed on missing, stale, malformed, or contradictory lifecycle state

Phase 54 should not introduce a second revocation ledger, a generic VC
`credentialStatus` rewrite, or a public status-list network. The current ARC
passport lifecycle model is already richer than pure revocation because it
includes supersession and operator-scoped distribution. The correct move is to
project that model outward, not replace it.

## Current State

### 1. ARC already ships operator-owned passport lifecycle truth

The current lifecycle substrate is stronger than a new phase-54 design should
pretend:

- `crates/arc-credentials/src/passport.rs` defines:
  - `PassportLifecycleState`
  - `PassportStatusDistribution`
  - `PassportLifecycleRecord`
  - `PassportLifecycleResolution`
- `crates/arc-cli/src/passport_verifier.rs` ships:
  - `PassportStatusRegistry`
  - `publish`, `resolve_for_passport`, `resolve`, and `revoke`
  - same-subject same-issuer-set supersession during republish
- `crates/arc-cli/src/passport.rs` exposes local CLI lifecycle operations:
  - `passport status publish`
  - `passport status list`
  - `passport status get`
  - `passport status resolve`
  - `passport status revoke`
- `crates/arc-cli/src/trust_control.rs` exposes the same lifecycle operations
  through remote trust-control routes
- `docs/AGENT_PASSPORT_GUIDE.md` already documents:
  - `active`
  - `superseded`
  - `revoked`
  - `notFound`
  - explicit operator publication
  - trust-control resolve URLs
  - DID discovery via `ArcPassportStatusService`

This means phase 54 does not need to invent lifecycle semantics. It needs to
make the existing semantics portable and attached to the new issuance path.

### 2. Phase 53 added OID4VCI-compatible issuance, but not lifecycle linkage

The codebase now has one narrow issuance lane:

- `crates/arc-credentials/src/oid4vci.rs` defines:
  - issuer metadata
  - credential offer
  - token request/response
  - credential request/response
  - the ARC-specific profile with configuration id
    `arc_agent_passport`
  - format `arc-agent-passport+json`
- `crates/arc-cli/src/passport_verifier.rs` persists one-time issuance offer
  state in `PassportIssuanceOfferRegistry`
- `crates/arc-cli/src/passport.rs` exposes local CLI issuance commands
- `crates/arc-cli/src/trust_control.rs` exposes remote metadata, offer, token,
  and credential routes
- `docs/AGENT_PASSPORT_GUIDE.md`, `spec/PROTOCOL.md`, and
  `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` explicitly frame this as a
  conservative transport/profile layer, not a credential rewrite

That phase-53 work is the right substrate for phase 54, but the delivered
credential flow still stops at "here is the passport artifact." It does not
yet say:

- where a holder or verifier should resolve current lifecycle state
- whether lifecycle support is guaranteed for this issuer profile
- whether the issued artifact was published into lifecycle state before
  delivery
- how to interpret stale cache or missing lifecycle state

### 3. The current status model is already portable enough to reuse directly

The existing lifecycle fields are already close to what a portable consumer
needs:

- `passport_id`
- `subject`
- `issuers`
- `issuer_count`
- `state`
- `published_at`
- `superseded_by`
- `revoked_at`
- `revoked_reason`
- `distribution.resolve_urls`
- `distribution.cache_ttl_secs`
- `valid_until`

That is materially better for phase 54 than inventing a new minimal revocation
boolean. It preserves ARC's richer lifecycle semantics and does not require a
new truth store.

### 4. The current lifecycle validator is intentionally minimal

`verify_passport_lifecycle_record` in
`crates/arc-cli/src/passport_verifier.rs` currently checks:

- non-empty `passport_id`
- non-empty `subject`
- sorted unique issuers and matching `issuer_count`
- persistent records cannot use `NotFound`

It does not yet fully enforce state-field coherence such as:

- `revoked_at` or `revoked_reason` only appearing with `Revoked`
- `superseded_by` rules for `Superseded` versus `Revoked`
- non-empty `resolve_urls` when an issued credential is advertised as
  lifecycle-portable
- stale distribution semantics beyond the optional cache TTL hint

That gap is acceptable for the current operator-facing lifecycle registry, but
phase 54 should tighten it before claiming portable lifecycle contracts.

## Gap Analysis

### Gap 1: No issuance-time lifecycle contract

The OID4VCI-compatible issuance profile does not yet advertise lifecycle
support in issuer metadata, offer state, or credential response metadata.

Consequence:

- external holders can redeem a credential without learning where to resolve
  current lifecycle state
- verifiers can only discover lifecycle through ARC-specific out-of-band docs
  or DID service resolution
- lifecycle support is not explicit in the issuance contract

### Gap 2: No portable status-reference sidecar for delivered credentials

The delivered credential remains an `AgentPassport`, which is correct. But the
delivery response does not yet carry a typed status/distribution reference that
binds the delivered artifact to operator-published lifecycle state.

Consequence:

- portable consumers have to guess lifecycle discovery
- the issuance lane and the lifecycle lane remain adjacent rather than joined

### Gap 3: No fail-closed issuance rule tying distribution to publication

Current issuance can deliver a passport even when there is no lifecycle record
or no published resolve URL for that passport.

Consequence:

- ARC could claim portable issuance without portable lifecycle truth
- a holder may receive a credential that has no discoverable lifecycle source

### Gap 4: No formal stale/contradictory lifecycle contract for portable consumers

`PassportStatusDistribution` already carries `cache_ttl_secs`, but the portable
consumer contract is still undocumented and unwired for the issuance path.

Consequence:

- holders and verifiers do not have a standards-facing answer to:
  - when cached lifecycle state expires
  - what to do if the resolve URL is unreachable
  - how to treat malformed or contradictory lifecycle records

### Gap 5: No explicit distribution distinction between current truth and holder transport

The codebase already has:

- lifecycle publication and resolution
- DID service discovery
- OID4VCI delivery

But phase 54 still needs to clearly separate:

- lifecycle truth discovery
- credential delivery
- holder presentation transport

Without that boundary, it would be easy to accidentally push phase-55 wallet
semantics into phase 54.

## Recommended Direction

### Recommendation 1: Keep the existing lifecycle registry as the only mutable truth

Phase 54 should keep these as the authoritative lifecycle substrate:

- `PassportStatusRegistry`
- `PassportLifecycleRecord`
- `PassportLifecycleResolution`
- `PassportStatusDistribution`

That means:

- no second revocation database
- no separate public status list as the primary truth
- no attempt to mutate signed passport artifacts when state changes

Portable lifecycle should be a projection layer over this registry.

### Recommendation 2: Add one small typed status-reference contract

Phase 54 likely needs one new typed contract that can be attached to issuance
surfaces without changing the signed credential.

Conservative candidate shape:

```json
{
  "passportId": "sha256:...",
  "resolveUrls": [
    "https://trust.example.com/v1/passport/statuses/resolve"
  ],
  "cacheTtlSecs": 300
}
```

Purpose:

- tell holders or verifiers where lifecycle truth lives
- keep the actual mutable state in the resolve document
- avoid baking mutable revocation state into the signed passport

This should be treated as sidecar metadata, not as a replacement for
`PassportLifecycleResolution`.

### Recommendation 3: Reuse `PassportLifecycleResolution` as the portable resolution document

The current resolution document is already the best candidate for the portable
query result.

Reasons:

- it already models the four lifecycle states ARC actually supports
- it already preserves supersession as first-class lifecycle truth
- it already includes distribution and validity fields
- it already maps to existing local and remote resolution behavior

Phase 54 should prefer tightening and documenting this shape over inventing a
second portable JSON schema with less information.

### Recommendation 4: Advertise lifecycle support in the ARC OID4VCI profile

The phase-53 OID4VCI profile already has an ARC-specific `arc_profile`
extension space. Phase 54 should use that same profile layer to advertise
lifecycle support.

Conservative metadata direction:

- issuer metadata advertises that ARC passport issuance supports lifecycle
  resolution
- the profile indicates lifecycle is operator-scoped and bound to the existing
  trust-control or DID-discovered resolution paths
- credential delivery includes a per-artifact status reference

This keeps lifecycle discoverability close to the issuance contract while still
preserving ARC-specific semantics.

### Recommendation 5: Require explicit publication before portable distribution

The safest phase-54 behavior is:

- if an operator wants portable lifecycle semantics for issued passports,
  lifecycle publication must already exist for that passport or be created
  explicitly as part of an operator action
- if lifecycle publication or status distribution is missing, issuance that
  claims portable lifecycle support must fail closed

What phase 54 should avoid:

- silently issuing a "portable" credential that has no lifecycle resolution
  path
- silently auto-publishing lifecycle state behind the operator's back

A conservative policy is to make publication explicit and distribution
mandatory when using the portable issuance profile.

### Recommendation 6: Treat DID service discovery as compatible, not primary truth

The current `ArcPassportStatusService` DID service entry is a useful discovery
path and should remain supported.

But for phase 54:

- the per-issued-credential status reference is the immediate distribution hint
- DID discovery remains a secondary discovery mechanism
- both should ultimately point to the same operator-owned lifecycle truth

This avoids creating separate discovery planes with different semantics.

## Proposed Contract Set

### A. Portable status reference

Minimal sidecar object carried by:

- OID4VCI issuer metadata ARC profile
- issuance offer context if needed
- credential response metadata
- optional local CLI output

Suggested fields:

- `passport_id`
- `resolve_urls`
- `cache_ttl_secs`

Optional fields only if clearly needed:

- `published_at`
- `distribution_source`

Avoid adding fields that create a second trust model.

### B. Portable lifecycle resolution document

Reuse or version the current `PassportLifecycleResolution` transport shape as
the canonical lifecycle response for portable consumers.

Required semantics:

- `active`
- `superseded`
- `revoked`
- `notFound`

Required failure behavior:

- malformed response fails closed
- missing required fields fails closed
- contradictory state fields fail closed
- expired cache without refresh path should not be treated as healthy state

### C. Issuer-profile lifecycle capability advertisement

Extend the ARC-specific issuance profile to say:

- this issuer supports portable lifecycle resolution for ARC passports
- the status resolution plane is operator-owned
- public discovery is not implied
- the delivered credential is still an ARC passport rather than a generic VC

This should stay inside ARC's profile extension layer, not a generic VC claim.

## Lifecycle Semantics To Preserve

### Immutable artifact, mutable lifecycle

This must remain true:

- the signed passport artifact does not change when superseded or revoked
- current lifecycle state is resolved through operator-managed distribution
  state

That is already how ARC works. Phase 54 should carry that model outward.

### Supersession is not revocation

ARC already distinguishes:

- `superseded`: newer passport replaced this one for the same subject and
  issuer set
- `revoked`: explicit operator revocation

That distinction is strategically important. Generic revocation-only models are
too weak for ARC's intended portability because they lose the difference
between "no longer current" and "actively invalidated."

### `notFound` is not healthy

Portable consumers should treat `notFound` as unresolved or non-current, not
as implicitly active.

This is especially important for:

- relying parties that require active lifecycle verification
- holders operating from cached or offline state

### Stale state is not healthy

If a consumer is operating beyond the published TTL and cannot refresh, the
portable lifecycle contract should require fail-closed behavior rather than
optimistic reuse of stale active state.

## Architecture Patterns

### Pattern 1: Projection, not replacement

**What:** Reuse the lifecycle registry as truth and expose it through portable
references plus portable resolution responses.

**Why:** This keeps supersession, revocation, and operator provenance aligned
with already shipped ARC behavior.

### Pattern 2: Sidecar lifecycle reference, not signed-credential mutation

**What:** Attach lifecycle discovery metadata beside the issued credential or
inside ARC profile metadata instead of modifying the signed passport format.

**Why:** Revocation and supersession are mutable. Mutating the credential would
collapse artifact truth and lifecycle truth into one unstable document.

### Pattern 3: Operator-scoped distribution only

**What:** Resolve lifecycle through operator-published URLs and optional DID
service discovery.

**Why:** This is compatible with ARC's existing trust boundary and does not
introduce public global discovery.

### Pattern 4: Explicit publication gate

**What:** Do not allow portable lifecycle claims unless lifecycle publication
exists.

**Why:** Issuance without lifecycle discoverability undermines the whole point
of phase 54.

## Standards and Interop Stance

### What phase 54 should say yes to

- ARC-specific lifecycle contracts attached to the ARC OID4VCI issuance profile
- operator-owned HTTPS lifecycle resolution
- DID service discovery that points to the same operator-owned resolution plane
- explicit supersession and revocation semantics

### What phase 54 should not claim yet

- generic `ldp_vc`, `jwt_vc_json`, or SD-JWT VC lifecycle compatibility
- a public status-list ecosystem
- wallet push distribution or presentation exchange
- public issuer discovery or a global status registry

### Why not jump directly to generic VC `credentialStatus`

The delivered credential is still an ARC-native `AgentPassport`, not a generic
W3C VC profile. Rewriting lifecycle into generic VC status vocabulary now would
either:

- overclaim compatibility ARC does not yet ship
- require a credential rewrite phase that this milestone explicitly deferred
- weaken ARC's richer supersession semantics

Phase 54 should first make ARC lifecycle truth portable on its own terms.
Later phases can add compatibility adapters where that is actually proven.

## Anti-Patterns To Avoid

- Do not create a second revocation store separate from
  `PassportStatusRegistry`.
- Do not silently issue lifecycle-portable credentials without a published
  resolve URL.
- Do not mutate signed passport JSON to insert current status.
- Do not treat the OID4VCI `credential_issuer` HTTPS origin as the trust root
  for passport validity.
- Do not collapse `superseded` into `revoked`.
- Do not treat `notFound` or stale cached state as implicitly active.
- Do not pull holder presentation transport into this phase.

## Likely Phase-54 Work Breakdown

### 54-01: Define portable status, revocation, and supersession contracts

Expected work:

- add typed status-reference and lifecycle-profile contract types in
  `arc-credentials`
- decide whether `PassportLifecycleResolution` is reused directly or wrapped in
  a versioned transport envelope
- define fail-closed validation for contradictory lifecycle state
- define how the OID4VCI ARC profile advertises lifecycle capability

### 54-02: Implement status publication, query, and lifecycle wiring

Expected work:

- thread lifecycle-reference metadata through local CLI issuance surfaces
- thread lifecycle-reference metadata through trust-control issuer metadata and
  credential delivery surfaces
- require explicit lifecycle publication or equivalent configured distribution
  before a credential can claim portable lifecycle support
- preserve existing local and remote publish/list/get/resolve/revoke behavior
  as the mutable truth plane

### 54-03: Docs and regression coverage

Expected work:

- update `docs/AGENT_PASSPORT_GUIDE.md`
- update `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
- update `spec/PROTOCOL.md`
- add local and remote regressions proving:
  - portable issuance advertises lifecycle support
  - issued credentials expose a lifecycle reference
  - superseded and revoked passports resolve truthfully after issuance
  - missing lifecycle publication fails closed
  - stale or malformed lifecycle state does not report healthy status

## Verification Focus

The highest-signal phase-54 tests should prove:

1. local issuance plus status publish results in a delivered credential with a
   usable lifecycle reference
2. remote trust-control issuer metadata advertises lifecycle support only when
   the operator has configured the required status substrate
3. superseding a published passport updates resolve results for old and new
   credentials without mutating either signed artifact
4. revocation remains explicit and observable through the same portable
   lifecycle contract
5. an issuance attempt that claims portable lifecycle but lacks publication or
   distribution data fails closed
6. malformed or contradictory lifecycle records are rejected before they are
   served as portable truth

## Recommended Non-Goals For Phase 54

- generic wallet ingestion UX
- wallet push notifications
- presentation requests or holder proof transport
- public issuer directories
- public status-list aggregation across issuers
- translation of ARC passports into generic VC formats

Those are either phase 55, phase 56, or intentionally out of scope for the
current trust boundary.

## References

Primary planning references:

- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`
- `docs/research/DEEP_RESEARCH_1.md`

Current lifecycle and issuance code:

- `crates/arc-credentials/src/lib.rs`
- `crates/arc-credentials/src/passport.rs`
- `crates/arc-credentials/src/oid4vci.rs`
- `crates/arc-cli/src/passport.rs`
- `crates/arc-cli/src/passport_verifier.rs`
- `crates/arc-cli/src/trust_control.rs`
- `crates/arc-cli/tests/passport.rs`

Current docs:

- `docs/AGENT_PASSPORT_GUIDE.md`
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
- `spec/PROTOCOL.md`

Phase-53 carry-forward context:

- `.planning/phases/53-oid4vci-compatible-issuance-and-delivery/53-CONTEXT.md`
- `.planning/phases/53-oid4vci-compatible-issuance-and-delivery/53-RESEARCH.md`

---

*Phase: 54-credential-status-revocation-and-distribution-contracts*
*Research completed: 2026-03-27*
