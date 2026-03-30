# Phase 24: Standards Submission and Launch Readiness - Context

**Gathered:** 2026-03-25
**Status:** Completed

<domain>
## Phase Boundary

Phase 24 closes the final `v2.3` launch gap. The focus is aligning release
docs, SDK docs, and the repo entrypoint to the current production-candidate
contract, then producing the standards and launch evidence that makes the
milestone auditable.

</domain>

<decisions>
## Implementation Decisions

### Documentation Alignment
- Update release-facing docs from stale `v1` wording to the current `v2.3`
  production-candidate framing.
- Fix the TypeScript SDK README to use the actual published package name
  `@arc-protocol/sdk`.
- Keep Python and Go SDKs in documented beta posture, but align them to the
  current protocol and release docs.

### Standards Artifacts
- Produce concrete repository-local standards profiles for receipts and
  portable trust instead of pretending formal submission has already happened.
- Keep those profiles scoped to the artifacts that actually ship today.

### Launch Evidence
- Use a GA checklist, risk register, and updated release audit as the launch
  closeout evidence.
- Treat hosted workflow observation as a remaining gate, not something to imply
  happened locally.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 24 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `PROD-13`, `PROD-14`
- `README.md` -- repository entrypoint
- `packages/sdk/arc-ts/README.md` -- TypeScript SDK release surface
- `packages/sdk/arc-py/README.md` -- Python SDK release posture
- `packages/sdk/arc-go/README.md` -- Go SDK release posture
- `docs/release/RELEASE_CANDIDATE.md` -- supported candidate surface
- `docs/release/RELEASE_AUDIT.md` -- go/no-go record
- `docs/release/GA_CHECKLIST.md` -- launch checklist
- `docs/release/RISK_REGISTER.md` -- known remaining risks
- `docs/standards/ARC_RECEIPTS_PROFILE.md` -- receipts standards profile
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` -- portable-trust standards profile

</canonical_refs>

<code_context>
## Existing Code Insights

- The production qualification lane for dashboard and SDK packages already
  existed after Phase 22; the remaining gap was doc and launch-surface
  alignment.
- `packages/sdk/arc-ts/package.json` already declared the real package name
  `@arc-protocol/sdk`, but the README still advertised `@arc/sdk`.
- The main README and release-candidate docs were still written against the
  older scoped `v1` framing even though the repository now ships broader
  portable-trust, certification, and A2A surfaces.
- There were no dedicated standards-submission drafts or GA/risk closeout docs
  yet.

</code_context>

<deferred>
## Deferred Ideas

- Expand the standards docs into formal public submission packets when the
  external submission venue and process are selected.
- Add public publication automation for the beta SDKs in a later milestone.
- Revisit GA wording after hosted CI and release qualification results are
  available for the final candidate commit.

</deferred>

---

*Phase: 24-standards-submission-and-launch-readiness*
*Context gathered: 2026-03-25*
