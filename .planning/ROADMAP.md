# Roadmap: PACT

## Milestones

- [x] **v1.0 Closing Cycle** - Phases 1-6 (shipped 2026-03-20)
- [x] **v2.0 Agent Economy Foundation** - Phases 7-12 (shipped 2026-03-24)
- [x] **v2.1 Federation and Verifier Completion** - Phases 13-16 (shipped 2026-03-24)
- [x] **v2.2 A2A and Ecosystem Hardening** - Phases 17-20 (completed 2026-03-25)
- [ ] **v2.3 Production and Standards** - planned
- [ ] **v2.4 Commercial Trust Primitives** - planned

## Archived Milestone

- `v2.1` roadmap: `.planning/milestones/v2.1-ROADMAP.md`
- `v2.1` requirements: `.planning/milestones/v2.1-REQUIREMENTS.md`
- `v2.1` audit: `.planning/milestones/v2.1-MILESTONE-AUDIT.md`
- `v2.2` roadmap: `.planning/milestones/v2.2-ROADMAP.md`
- `v2.2` requirements: `.planning/milestones/v2.2-REQUIREMENTS.md`
- `v2.2` audit: `.planning/milestones/v2.2-MILESTONE-AUDIT.md`

## Current Milestone: v2.2 A2A and Ecosystem Hardening

**Milestone Goal:** Turn the shipped A2A adapter and certification skeleton into partner-hardened, operator-usable surfaces by closing the remaining auth/lifecycle gaps, adding certification registry distribution, and shipping the conformance/docs needed for real onboarding.
**Status:** Complete on 2026-03-25. Archived snapshots now exist under
`.planning/milestones/`; the next milestone definition has not been created yet.

**Phase Numbering:**
- Integer phases 17-20: planned v2.2 milestone work
- Future milestones continue from phase 21 onward

- [x] **Phase 17: A2A Auth Matrix and Partner Admission Hardening** - Close the remaining auth-matrix gaps, including provider-specific and non-header credential delivery, while keeping partner admission fail closed and operator-visible.
- [x] **Phase 18: Durable A2A Task Lifecycle and Federation Hardening** - Complete long-running task recovery, follow-up correlation, and per-partner federation/request-shaping isolation for mediated A2A work.
- [x] **Phase 19: Certification Registry and Trust Distribution** - Turn signed certification checks into registry-backed artifact publication, lookup, verification, supersession, and revocation surfaces.
- [x] **Phase 20: Ecosystem Conformance and Operator Onboarding** - Harden the new A2A and certification lanes with conformance coverage, docs, examples, and operator/admin onboarding surfaces.

## Phase Details

### Phase 17: A2A Auth Matrix and Partner Admission Hardening
**Goal**: Operators can mediate the remaining A2A peer auth schemes without bespoke glue while keeping negotiation, partner admission, and diagnostics fail closed.
**Depends on**: Phase 16 and shipped A2A alpha
**Requirements**: A2A-01, A2A-02
**Success Criteria** (what must be TRUE):
  1. An operator can configure provider-specific or non-header A2A credentials through explicit adapter or admin surfaces rather than patching per-call request code.
  2. The adapter negotiates partner auth requirements fail closed across the remaining supported scheme matrix and never silently downgrades auth.
  3. Rejected partner auth setups explain which security requirement, credential binding, or tenant context caused denial.
  4. Integration coverage proves the new auth lanes through mediated A2A calls and truthful receipt generation.
**Plans**: 3 plans completed

Plans:
- [x] 17-01: Define the remaining A2A auth-scheme model, config surfaces, and partner-admission contract.
- [x] 17-02: Implement provider-specific and non-header credential delivery plus fail-closed negotiation and diagnostics.
- [x] 17-03: Add fixtures, docs, and mediated integration tests for the completed auth matrix.

### Phase 18: Durable A2A Task Lifecycle and Federation Hardening
**Goal**: Long-running A2A work remains truthful and recoverable across reconnects, delayed completions, and per-partner federation boundaries.
**Depends on**: Phase 17
**Requirements**: A2A-03, A2A-04, A2A-05
**Success Criteria** (what must be TRUE):
  1. Long-running A2A tasks preserve the original capability binding and receipt semantics across reconnect, retry, and delayed follow-up paths.
  2. Push-notification and follow-up flows can be correlated back to the originating task and rejected when lifecycle state is inconsistent.
  3. Partner-specific federation/request-shaping policy can isolate tenant and org routing without widening trust across peers.
  4. Operator-facing evidence is sufficient to debug lifecycle or federation failures without replaying raw partner traffic by hand.
**Plans**: 3 plans completed

Plans:
- [x] 18-01: Define durable task-state recovery and lifecycle-correlation semantics for long-running A2A work.
- [x] 18-02: Implement reconnect, resume, and delayed-completion handling with fail-closed lifecycle validation.
- [x] 18-03: Add per-partner federation/request-shaping policy, diagnostics, and end-to-end lifecycle tests.

### Phase 19: Certification Registry and Trust Distribution
**Goal**: Signed certification artifacts become publishable and resolvable trust objects rather than local files only.
**Depends on**: Phase 18
**Requirements**: CERT-01, CERT-02
**Success Criteria** (what must be TRUE):
  1. Operators can publish and retrieve certification artifacts through a registry surface with stable identifiers and immutable artifact verification.
  2. The system can resolve the current certification status for a tool server, including active, superseded, and revoked states.
  3. CLI and service surfaces can verify registry-backed certification artifacts without bespoke glue code or manual file coordination.
  4. Certification registry flows remain fail closed when artifact signatures, digests, or trust metadata do not match.
**Plans**: 3 plans completed

Plans:
- [x] 19-01: Define certification registry artifact IDs, metadata, storage semantics, and status model.
- [x] 19-02: Implement publish/query/resolve/revoke flows across CLI and trust-control surfaces.
- [x] 19-03: Add verification, supersession/revocation handling, and integration coverage for registry-backed certification.

### Phase 20: Ecosystem Conformance and Operator Onboarding
**Goal**: The new A2A and certification surfaces are supportable and adoptable by operators and design partners.
**Depends on**: Phase 19
**Requirements**: ECO-01, ECO-02
**Success Criteria** (what must be TRUE):
  1. Conformance and CI lanes prove the newly shipped A2A auth, lifecycle, and certification-registry flows across supported operator surfaces.
  2. Operators can onboard an A2A partner and a certified tool server by following docs and examples rather than inspecting source code.
  3. Admin, reporting, and example surfaces expose enough context to support partner onboarding and troubleshooting.
  4. The v2.2 milestone exits with docs, fixtures, and regression coverage aligned to the shipped behavior.
**Plans**: 3 plans completed

Plans:
- [x] 20-01: Extend conformance fixtures and CI coverage for the new A2A auth, lifecycle, and certification-registry lanes.
- [x] 20-02: Add operator/admin docs, examples, and onboarding guides for A2A partners and certified tool servers.
- [x] 20-03: Harden partner-facing reporting and regression coverage for milestone closeout.

## Future Milestone Outline

- **v2.2 A2A and Ecosystem Hardening**
  Remaining A2A auth matrix and provider-specific hardening, deeper long-running lifecycle coverage, certification registry/storage, and operator onboarding.
- **v2.3 Production and Standards**
  Protocol specification v2 alignment, deployment/runbook/launch hardening, and standards submission.
- **v2.4 Commercial Trust Primitives**
  Insurer-facing data feed, marketplace trust primitives, and reputation federation.

## Progress

**Execution Order:**
v1.0, v2.0, v2.1, and v2.2 are complete. The next milestone definition will
start v2.3 at Phase 21.

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. E9 HA Trust-Control Reliability | v1.0 | 4/4 | Complete | 2026-03-19 |
| 2. E12 Security Boundary Completion | v1.0 | 4/4 | Complete | 2026-03-19 |
| 3. E10 Remote Runtime Hardening | v1.0 | 4/4 | Complete | 2026-03-19 |
| 4. E11 Cross-Transport Concurrency Semantics | v1.0 | 4/4 | Complete | 2026-03-20 |
| 5. E13 Policy and Adoption Unification | v1.0 | 4/4 | Complete | 2026-03-19 |
| 6. E14 Hardening and Release Candidate | v1.0 | 4/4 | Complete | 2026-03-20 |
| 7. Schema Compatibility and Monetary Foundation | v2.0 | 2/2 | Complete | 2026-03-22 |
| 8. Core Enforcement | v2.0 | 4/4 | Complete | 2026-03-22 |
| 9. Compliance and DPoP | v2.0 | 3/3 | Complete | 2026-03-24 |
| 10. Receipt Query API and TypeScript SDK 1.0 | v2.0 | 3/3 | Complete | 2026-03-23 |
| 11. SIEM Integration | v2.0 | 3/3 | Complete | 2026-03-23 |
| 12. Capability Lineage Index and Receipt Dashboard | v2.0 | 4/4 | Complete | 2026-03-23 |
| 13. Enterprise Federation Administration | v2.1 | 4/4 | Complete | 2026-03-24 |
| 14. Portable Verifier Distribution and Replay Safety | v2.1 | 4/4 | Complete | 2026-03-24 |
| 15. Multi-Issuer Passport Composition | v2.1 | 3/3 | Complete | 2026-03-24 |
| 16. Cross-Org Shared Evidence Analytics | v2.1 | 4/4 | Complete | 2026-03-24 |
| 17. A2A Auth Matrix and Partner Admission Hardening | v2.2 | 3/3 | Complete | 2026-03-25 |
| 18. Durable A2A Task Lifecycle and Federation Hardening | v2.2 | 3/3 | Complete | 2026-03-25 |
| 19. Certification Registry and Trust Distribution | v2.2 | 3/3 | Complete | 2026-03-25 |
| 20. Ecosystem Conformance and Operator Onboarding | v2.2 | 3/3 | Complete | 2026-03-25 |
