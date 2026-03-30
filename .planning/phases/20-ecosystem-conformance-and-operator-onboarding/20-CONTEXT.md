# Phase 20: Ecosystem Conformance and Operator Onboarding - Context

**Gathered:** 2026-03-25
**Status:** Completed

<domain>
## Phase Boundary

Phase 20 closes v2.2 by making the new A2A and certification surfaces
supportable. The focus is regression coverage, operator docs, and milestone
closeout artifacts rather than another protocol expansion.

</domain>

<decisions>
## Implementation Decisions

### Conformance and Regression
- Reuse the strongest existing adapter and CLI integration suites instead of
  inventing a parallel conformance harness.
- Treat provider-admin regression as the safety check for trust-control admin
  compatibility after certification registry changes.

### Operator Onboarding
- Put operator guidance in the existing A2A and certification guides.
- Document only shipped behavior: request shaping, partner admission, durable
  task correlation, and registry-backed certification.

### Milestone Closeout
- Capture the phase history in context, plan, summary, validation, and
  verification files.
- Update roadmap, requirements, project state, and milestone summaries so v2.2
  is traceably complete.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 20 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `ECO-01`, `ECO-02`
- `docs/A2A_ADAPTER_GUIDE.md` -- A2A operator onboarding
- `docs/ARC_CERTIFY_GUIDE.md` -- certification operator onboarding
- `docs/CHANGELOG.md` -- operator-visible milestone delta
- `crates/arc-cli/tests/certify.rs` -- certification conformance coverage
- `crates/arc-cli/tests/provider_admin.rs` -- remote admin regression coverage

</canonical_refs>

<code_context>
## Existing Code Insights

- The main missing v2.2 gap after Phases 17 through 19 was supportability, not
  a missing core substrate.
- The adapter library suite already exercises mediated A2A flows deeply enough
  to act as the conformance lane for the new auth and lifecycle work.
- Certification onboarding belongs in the existing guide and changelog rather
  than a new product area.

</code_context>

<deferred>
## Deferred Ideas

- dedicated CI job fan-out for A2A partner fixtures
- richer admin UI for certification registry management
- partner onboarding dashboards beyond CLI and docs

</deferred>

---

*Phase: 20-ecosystem-conformance-and-operator-onboarding*
*Context gathered: 2026-03-25*
