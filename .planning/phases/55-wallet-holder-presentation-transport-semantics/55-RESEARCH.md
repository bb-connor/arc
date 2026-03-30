# Phase 55: Wallet / Holder Presentation Transport Semantics - Research

**Researched:** 2026-03-28
**Domain:** Holder-facing transport over ARC passport challenge/presentation
**Confidence:** HIGH

<phase_alignment>
## Phase Alignment

The phase-55 executable plan files are not yet present in this directory, so
this memo is aligned conservatively to:

- `.planning/ROADMAP.md` phase 55
- `.planning/REQUIREMENTS.md` requirements `VC-03` and `VC-05`
- the current passport challenge/presentation implementation
- the phase-53 OID4VCI issuance lane
- the phase-54 lifecycle distribution outcome now reflected in docs and code

This memo assumes phases 53 and 54 are the current baseline:

- ARC can issue passports through a conservative OID4VCI-compatible flow
- delivered credentials can carry a portable lifecycle reference
- trust-control can expose a public read-only lifecycle resolve plane

Phase 55 therefore starts after credential delivery and lifecycle discovery are
already in place.
</phase_alignment>

<user_constraints>
## Locked Constraints

### Trust boundary

- Preserve the current ARC-native trust model:
  - `did:arc` remains the holder and issuer identifier model
  - Ed25519-signed ARC passport credentials remain the credential truth
  - holder proof remains the existing signed ARC presentation response model
- Keep verifier authority explicit and bounded:
  - verifier identity stays challenge-bound
  - lifecycle enforcement stays policy-bound and fail-closed
  - remote transport must not silently widen authority or trust

### Phase scope

- Build on the shipped `PassportPresentationChallenge` and
  `PassportPresentationResponse` model.
- Build on the phase-54 lifecycle distribution and resolution contract rather
  than inventing a separate lifecycle check.
- Focus on holder-facing transport semantics for request retrieval, response
  submission, and bounded result handling.
- Do not pull external compatibility proof or qualification into this phase.
  That remains phase 56.

### Deliberate non-goals

- no generic wallet ecosystem claim
- no OpenID4VP or SIOP compatibility claim
- no zero-knowledge or SD-JWT style selective disclosure
- no DIDComm, push notification, or mobile wallet messaging stack
- no public verifier marketplace or public request directory
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| VC-03 | ARC defines holder-facing presentation and transport semantics beyond direct file exchange so wallets and remote relying parties can use the passport layer cleanly. | Reuse the existing challenge and signed presentation response as proof artifacts, and add one ARC-native transport contract for request-by-reference plus submit-by-reference over HTTPS. |
| VC-05 | Broader credential interop preserves ARC's conservative rules against synthetic global trust, silent federation, and authority widening. | Keep the transport ARC-specific, bind every exchange to the existing verifier challenge, preserve `did:arc` holder proof, and avoid claiming broader wallet or verifier standards compatibility before phase 56. |
</phase_requirements>

## Summary

After phases 53 and 54, ARC now has:

- holder credential delivery through OID4VCI-compatible issuance
- portable lifecycle distribution for issued passports
- replay-safe verifier challenge state
- signed holder presentation responses
- local and remote verifier evaluation

The remaining gap is transport, not proof semantics.

Today the holder path is still effectively file-based:

- a verifier or operator creates a `PassportPresentationChallenge`
- the holder receives that JSON out of band
- the holder signs a `PassportPresentationResponse`
- the verifier receives that JSON out of band or via an authenticated admin
  path

That is sufficient for local tooling and protocol proof, but it is not yet a
holder-facing wallet transport story. The conservative phase-55 move is to add
one ARC-native HTTPS transport profile around the existing challenge and
response artifacts:

1. verifier/admin creates a transportable presentation request
2. holder retrieves that request by reference from a public read-only endpoint
3. holder submits the signed presentation response to a public holder submit
   endpoint
4. verifier/admin can inspect the persisted verification result through
   existing or adjacent admin surfaces

The critical design rule is: keep the proof artifact unchanged. Phase 55 should
transport the existing challenge and response, not replace them.

## Current State

### 1. ARC already has the core proof model

`crates/arc-credentials/src/challenge.rs` and
`crates/arc-credentials/src/presentation.rs` already define:

- `PassportPresentationChallenge`
- `PassportPresentationResponse`
- `PassportPresentationVerification`
- holder proof-of-possession bound to the passport subject `did:arc`
- verifier challenge freshness with `issued_at`, `expires_at`, `nonce`
- optional `challenge_id`
- selective disclosure hints with `issuer_allowlist` and `max_credentials`
- verifier policy binding through embedded policy or `policyRef`

Current cryptographic behavior is already conservative and useful:

- holder must possess the subject key
- verifier checks challenge freshness and signature
- verifier can evaluate policy
- replay-safe consumption exists when a challenge store is configured

Phase 55 should preserve all of that.

### 2. ARC already has lifecycle-aware verification

After phase 54, the presentation lane also has portable lifecycle support:

- issued credentials may carry `arcCredentialContext.passportStatus`
- issuer metadata may advertise `arcProfile.passportStatusDistribution`
- trust-control exposes `GET /v1/public/passport/statuses/resolve/{passport_id}`
- evaluation and challenge verification can enforce
  `requireActiveLifecycle: true`

That means phase 55 does not need a second lifecycle transport. It should use
the existing status reference and verifier-side resolution model.

### 3. ARC already has remote verifier endpoints, but they are not holder-facing

Current trust-control routes include:

- `POST /v1/passport/challenges`
- `POST /v1/passport/challenges/verify`

Those routes are verifier/admin plane routes behind the service-token
boundary. They are not a public holder transport surface.

The code confirms the gap:

- challenge creation is admin-authenticated
- challenge verification is admin-authenticated
- there is no public request retrieval path
- there is no public holder submission path
- there is no persisted presentation request/session object exposed to a holder

### 4. The docs already say the missing thing out loud

`docs/AGENT_PASSPORT_GUIDE.md` explicitly lists as not yet shipped:

- "wallet transport semantics beyond file-based challenge/response"

That is the exact phase-55 problem statement.

## Exact Gap After Phases 53-54

Phases 53 and 54 solved delivery and lifecycle truth. They did not solve
holder transport.

The exact remaining gap is:

1. the holder still receives challenges as raw files or bespoke out-of-band
   JSON
2. the holder still returns signed responses as raw files or verifier-managed
   manual exchange
3. trust-control has no public request-by-reference path for holders
4. trust-control has no public submit-by-reference path for holders
5. the issued credential response does not by itself tell a wallet how to
   participate in a remote presentation exchange

Put differently:

- the credential transport exists
- the lifecycle transport exists
- the presentation proof exists
- the presentation transport does not

## Recommended Direction

### Recommendation 1: Keep challenge and response artifacts unchanged

Phase 55 should continue to use:

- `PassportPresentationChallenge`
- `PassportPresentationResponse`
- `PassportPresentationVerification`

No new proof suite and no new presentation artifact should replace them.

Reason:

- the proof model is already challenge-bound, replay-aware, and subject-key
  bound
- replacing it would turn phase 55 into a new cryptographic protocol instead
  of a transport phase

### Recommendation 2: Add an ARC-native transport envelope around the challenge

Phase 55 should define one new request transport document that wraps the
existing challenge.

Conservative shape:

- one transport request id
- the existing `PassportPresentationChallenge`
- one holder submission URL
- one request retrieval URL or equivalent public reference
- one transport expiry that is equal to or stricter than the embedded
  challenge expiry

Important simplification:

- require `challengeId` for any transported request
- use `challengeId` as the transport correlation key

This avoids inventing a second identifier system.

### Recommendation 3: Add one holder submission envelope, not a new proof object

The holder should submit:

- the existing `PassportPresentationResponse`
- correlated to the transport request by `challengeId`

That means the transport submission can be a thin wrapper around the existing
response rather than a new proof format.

### Recommendation 4: Use public read + public submit, not public admin

The phase-55 transport surface should separate verifier/admin actions from
holder actions:

Verifier/admin:

- create presentation request
- inspect request state
- inspect verification result

Holder/public:

- fetch presentation request by reference
- submit signed presentation response

This matches the phase-53/54 pattern:

- OID4VCI metadata, token, credential: holder-facing read/redeem plane
- status resolve: public read-only plane
- publication and verifier policy CRUD: admin plane

### Recommendation 5: Keep lifecycle verification on the verifier side

The holder transport contract should not try to carry current lifecycle truth
inline.

Instead:

- the holder may use the phase-54 status reference as a preflight hint
- the verifier must still resolve lifecycle at verification time if policy
  requires it
- stale or contradictory lifecycle state remains fail-closed in verifier
  evaluation

This avoids duplicating or caching mutable lifecycle truth inside the transport
exchange.

### Recommendation 6: Return a minimal holder result, persist the full verifier result

The holder submit route should not need to expose every internal verifier
detail. A conservative split is:

- public holder submit returns a minimal result or receipt
- verifier/admin routes can read the full persisted
  `PassportPresentationVerification`

This prevents phase 55 from overexposing verifier-side policy internals while
still giving holders an actionable outcome.

## Conservative Contract Set

### A. `ArcPassportPresentationRequest`

Purpose:

- a transport wrapper around an existing `PassportPresentationChallenge`
- a public request-by-reference artifact for a holder or wallet

Suggested fields:

- `schema`
- `request_id`
- `challenge_id`
- `challenge`
- `retrieve_url`
- `submit_url`
- `expires_at`

Design notes:

- `challenge_id` should match `challenge.challengeId`
- `expires_at` must not exceed `challenge.expiresAt`
- the embedded challenge remains the cryptographic request artifact

### B. `ArcPassportPresentationSubmission`

Purpose:

- a transport wrapper for public holder submission

Suggested fields:

- `request_id`
- `challenge_id`
- `presentation`

Design notes:

- `presentation.challenge.challengeId` must match both `request_id` and
  `challenge_id`
- the service should reject submission if the transport request is expired,
  already completed, or does not match the embedded challenge

### C. `ArcPassportPresentationResult`

Purpose:

- a minimal public-facing result returned to the holder

Suggested fields:

- `request_id`
- `challenge_id`
- `verifier`
- `accepted`
- `passport_id`
- `replay_state`
- optional `policy_id`
- optional `lifecycle_state`

Design notes:

- this is not a replacement for `PassportPresentationVerification`
- it is only the holder-facing outcome summary

### D. Presentation request/session record

Purpose:

- durable trust-control state that binds request retrieval, response
  submission, replay safety, and verifier result inspection

Suggested stored fields:

- request envelope
- status enum such as `issued`, `submitted`, `verified`, `expired`
- stored submission payload
- stored verification result
- timestamps for issue, submit, verify, expire

This can reuse the same operational pattern as the existing SQLite-backed
verifier challenge store rather than inventing a new distributed coordination
system.

## Standard Stack

### Core

| Library | Purpose | Why |
|---------|---------|-----|
| `arc-credentials` | Source-of-truth challenge, response, verification, and status-reference types | Phase 55 should extend transport around existing ARC artifacts instead of replacing them. |
| `arc-cli` | Local holder/verifier tooling | Existing CLI commands already exercise create/respond/verify flows and should gain transport wrappers rather than a second proof path. |
| `axum` | Public request retrieval and holder submission routes | Trust-control already uses `axum`; no new HTTP stack is needed. |
| `rusqlite` | Durable request/session + replay-safe state | Existing replay-safe challenge storage already uses SQLite patterns. |
| `serde` / `serde_json` | Typed transport envelopes | ARC already models protocol artifacts this way. |

### Supporting

| Library | Purpose | When to Use |
|---------|---------|-------------|
| existing trust-control client helpers | remote request fetch and submission from CLI | Reuse current client patterns instead of inventing a separate holder HTTP client. |
| existing canonical JSON + Ed25519 signing | challenge and response proof verification | Already shipped and must remain the proof substrate. |

### Dependency posture

- No new external protocol library is required for the conservative phase-55
  transport profile.
- Do not add a generic wallet protocol library for this phase.

## Architecture Patterns

### Pattern 1: Transport wrapper over existing proof

**Use:** wrap `PassportPresentationChallenge` and
`PassportPresentationResponse` in small transport envelopes.

**Why:** the current proof model is already correct; the missing layer is
transport and correlation.

### Pattern 2: Challenge ID as session key

**Use:** require `challengeId` for any transport request and use it as the
durable correlation key.

**Why:** the field already exists, trust-control already emits it, and it
avoids an extra identifier layer.

### Pattern 3: Public holder plane, admin verifier plane

**Use:** expose public request fetch and submission routes while keeping
request creation, policy configuration, and detailed result inspection on the
authenticated admin plane.

**Why:** this preserves the current ARC operator boundary.

### Pattern 4: Synchronous verify, persisted result

**Use:** on holder submission, verify immediately when possible, consume the
challenge, and persist the verification result.

**Why:** current verification is deterministic and local to trust-control, so a
simple synchronous lane is enough for phase 55.

### Pattern 5: Lifecycle check remains verifier-side

**Use:** if a verifier policy requires active lifecycle, the submission flow
must resolve lifecycle at verify time using phase-54 status distribution.

**Why:** current lifecycle truth is mutable and must not be snapshotted inside
holder transport state.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Holder proof | A new signing or proof format | `PassportPresentationResponse` | It already binds holder key, challenge, and presented passport. |
| Presentation filtering | A new selective-disclosure subsystem | `present_agent_passport` plus challenge disclosure hints | Already shipped and bounded. |
| Replay safety | A new ad hoc token system | existing challenge-store style durable state keyed by `challengeId` | ARC already has the replay-safe pattern. |
| Lifecycle truth in transport | Inline mutable status claims in the presentation envelope | phase-54 status reference + verifier-side resolution | Keeps mutable status out of the signed/transported proof. |
| Wallet compatibility story | Full OpenID4VP or DIDComm | ARC-native request/submit transport profile | Phase 55 is transport semantics, not external standards qualification. |

## Common Pitfalls

- Duplicating identifiers:
  - if `request_id`, `challenge_id`, and `presentation.challenge.challengeId`
    can diverge, the transport becomes substitution-prone
- Smuggling verifier state into the holder contract:
  - the holder does not need full verifier internals to submit a presentation
- Snapshotting lifecycle too early:
  - lifecycle must be resolved when verifying, not frozen when issuing the
    request
- Turning public holder routes into public admin:
  - request creation and policy management must remain operator-authenticated
- Making the transport verifier-agnostic:
  - ARC presentation is verifier-bound; the transport should not imply a
    generic reusable bearer presentation
- Overclaiming interoperability:
  - ARC can say "holder-facing HTTPS transport for ARC challenges and
    presentations," not "generic wallet compatibility"

## Code Examples

### Example 1: Presentation request envelope

```json
{
  "schema": "arc.agent-passport-presentation-request.v1",
  "requestId": "f7d8...",
  "challengeId": "f7d8...",
  "retrieveUrl": "https://trust.example.com/v1/public/passport/presentation/requests/f7d8...",
  "submitUrl": "https://trust.example.com/v1/public/passport/presentation/submissions/f7d8...",
  "expiresAt": "2026-03-28T15:45:00Z",
  "challenge": {
    "schema": "arc.agent-passport-presentation-challenge.v1",
    "verifier": "https://rp.example.com",
    "challengeId": "f7d8...",
    "nonce": "1f92...",
    "issuedAt": "2026-03-28T15:40:00Z",
    "expiresAt": "2026-03-28T15:45:00Z",
    "policyRef": {
      "policyId": "rp-default"
    }
  }
}
```

### Example 2: Holder submission envelope

```json
{
  "schema": "arc.agent-passport-presentation-submission.v1",
  "requestId": "f7d8...",
  "challengeId": "f7d8...",
  "presentation": {
    "schema": "arc.agent-passport-presentation-response.v1",
    "challenge": {
      "schema": "arc.agent-passport-presentation-challenge.v1",
      "verifier": "https://rp.example.com",
      "challengeId": "f7d8...",
      "nonce": "1f92...",
      "issuedAt": "2026-03-28T15:40:00Z",
      "expiresAt": "2026-03-28T15:45:00Z"
    },
    "passport": { "...": "ARC passport artifact" },
    "proof": { "...": "holder proof" }
  }
}
```

### Example 3: Minimal holder result

```json
{
  "requestId": "f7d8...",
  "challengeId": "f7d8...",
  "verifier": "https://rp.example.com",
  "accepted": true,
  "passportId": "7b2a...",
  "replayState": "consumed",
  "policyId": "rp-default",
  "lifecycleState": "active"
}
```

## Proposed Work Breakdown

### 55-01: Define holder-facing transport contracts

Expected work:

- add typed request, submission, and holder-result envelopes in
  `arc-credentials`
- require `challengeId` for transported flows
- define validation rules that bind request id, challenge id, verifier, and
  expiry together

### 55-02: Implement transport surfaces

Expected work:

- local CLI support to fetch or materialize presentation requests and submit
  signed responses
- trust-control admin route to create presentation requests
- trust-control public route to retrieve a request by reference
- trust-control public holder route to submit a presentation response
- persisted request/session state plus stored verification result

### 55-03: Docs and regression coverage

Expected work:

- update `docs/AGENT_PASSPORT_GUIDE.md`
- update `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
- update `spec/PROTOCOL.md`
- add regressions for:
  - request retrieval
  - submission correlation
  - replay-safe duplicate submission rejection
  - stale request rejection
  - lifecycle fail-closed behavior during submission verification

## What Not To Do Yet

- Do not claim OpenID4VP, SIOP, or generic wallet interoperability.
- Do not invent a new presentation proof format.
- Do not move lifecycle truth into the request or response payload.
- Do not make presentation requests discoverable through a public directory.
- Do not add push channels, DIDComm, QR ceremonies, or mobile-app semantics in
  this phase.
- Do not overfit phase 55 to one external verifier. That proof belongs to
  phase 56.

## References

Planning and research:

- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `docs/research/DEEP_RESEARCH_1.md`
- `.planning/phases/54-credential-status-revocation-and-distribution-contracts/54-RESEARCH.md`

Code:

- `crates/arc-credentials/src/challenge.rs`
- `crates/arc-credentials/src/presentation.rs`
- `crates/arc-credentials/src/passport.rs`
- `crates/arc-credentials/src/oid4vci.rs`
- `crates/arc-cli/src/passport.rs`
- `crates/arc-cli/src/trust_control.rs`
- `crates/arc-cli/tests/passport.rs`

Docs and protocol:

- `docs/AGENT_PASSPORT_GUIDE.md`
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
- `spec/PROTOCOL.md`

---

*Phase: 55-wallet-holder-presentation-transport-semantics*
*Research completed: 2026-03-28*
