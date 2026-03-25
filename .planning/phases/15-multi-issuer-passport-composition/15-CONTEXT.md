# Phase 15: Multi-Issuer Passport Composition - Context

**Gathered:** 2026-03-24
**Status:** Completed

<domain>
## Phase Boundary

Phase 15 removes the alpha-era single-issuer restriction from passport
verification, evaluation, and presentation. PACT now accepts same-subject
passport bundles containing independently signed credentials from multiple
issuers, reports issuer identity explicitly, and keeps acceptance rules per
credential instead of inventing any cross-issuer aggregate truth. This phase
does not add a new multi-issuer aggregation score, wallet semantics, or a
special local compose command.

</domain>

<decisions>
## Implementation Decisions

### Composition Semantics
- A passport remains an unsigned bundle of independently verifiable reputation
  credentials.
- Every contained credential must still verify independently and must name the
  same passport subject.
- `valid_until` remains the minimum credential expiration across the bundle.
- Merkle roots remain the union of credential evidence roots.
- Multi-issuer composition does not create a synthetic bundle-level issuer.

### Verifier Semantics
- Passport verification reports `issuerCount` and the full `issuers` list.
- The legacy top-level `issuer` field is only populated when the bundle has
  exactly one issuer.
- Policy evaluation remains per credential. A passport is accepted when at
  least one credential satisfies the verifier policy; no cross-issuer score
  blending or weighted bundle average is introduced.
- Evaluation output must identify the issuer for each credential result and
  expose `matchedIssuers` for positive matches.

### CLI and Reporting
- `passport verify`, `passport evaluate`, `passport present`, and reputation
  compare must stay truthful for both single-issuer and multi-issuer bundles.
- `passport create` remains a single-issuer authoring helper because it is
  grounded in one local operator signing key and one local receipt corpus.

### Deferred
- No new `passport compose` authoring command in this phase
- No bundle-level aggregate score or trust synthesis across issuers
- No changes to verifier challenge or trust-control storage semantics beyond
  the multi-issuer-aware verification/reporting contract

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 15 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `PASS-01`, `PASS-02`
- `.planning/STATE.md` -- current milestone position after Phase 14
- `docs/AGENT_PASSPORT_GUIDE.md` -- shipped passport/verifier contract
- `crates/pact-credentials/src/lib.rs` -- core composition, verification, and
  evaluation semantics
- `crates/pact-cli/src/passport.rs` and `crates/pact-cli/src/reputation.rs` --
  user-facing reporting surfaces

</canonical_refs>

<code_context>
## Existing Code Insights

- `build_agent_passport` and `verify_agent_passport` previously hard-rejected
  multiple issuers even though the rest of evaluation logic already operated
  per credential.
- `evaluate_agent_passport` already evaluates every credential independently and
  only needed issuer-aware reporting to become truthful for multi-issuer
  bundles.
- `passport present` already supports issuer filtering and max-credential
  limits, which naturally generalize to multi-issuer bundles.
- `reputation compare` consumes `PassportVerification`, so top-level issuer
  reporting changes must stay compatible there.

</code_context>

<deferred>
## Deferred Ideas

- Automatic local composition tooling
- Cross-issuer aggregation or trust synthesis
- Shared remote evidence analytics and provenance reporting (Phase 16)

</deferred>

---

*Phase: 15-multi-issuer-passport-composition*
*Context gathered: 2026-03-24*
