# Roadmap: PACT

## v1.0 Closing Cycle

## Overview

The earlier PACT roadmap work already established the platform shape through the E0-E8 program. The current GSD milestone starts at the post-review closing cycle: stabilize clustered trust control, complete the missing security boundary, harden remote runtime behavior, unify concurrency semantics, simplify policy/adoption, and then qualify the whole surface for release.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: E9 HA Trust-Control Reliability** - Eliminate cluster flake paths and freeze the control-plane contract.
- [ ] **Phase 2: E12 Security Boundary Completion** - Turn roots into enforced runtime boundaries for filesystem-shaped access.
- [ ] **Phase 3: E10 Remote Runtime Hardening** - Make hosted Streamable HTTP lifecycle semantics reconnect-safe and operationally credible.
- [ ] **Phase 4: E11 Cross-Transport Concurrency Semantics** - Unify task, stream, cancellation, and late-event behavior across transports.
- [ ] **Phase 5: E13 Policy and Adoption Unification** - Collapse the split policy story and add a higher-level native adoption path.
- [ ] **Phase 6: E14 Hardening and Release Candidate** - Convert the closing-cycle work into explicit release-quality guarantees.

## Phase Details

### Phase 1: E9 HA Trust-Control Reliability
**Goal**: Make clustered trust-control deterministic enough that workspace and CI runs stop failing on leader/follower visibility races.
**Depends on**: Nothing (current closing-cycle entry phase)
**Requirements**: [HA-01, HA-02, HA-03, HA-04]
**Success Criteria** (what must be TRUE):
  1. Repeated workspace and targeted trust-cluster runs no longer flake on leader-side budget visibility.
  2. Forwarded writes return success only after the documented visibility guarantee is actually satisfied.
  3. Authority, revocation, receipt, and budget state remain correct across leader failover.
  4. Cluster status surfaces enough state to localize routing, cursor, and convergence failures quickly.
**Plans**: 4 plans

Plans:
- [x] 01-01: Reproduce the current trust-cluster flake and add observability for leader, follower, and cursor state.
- [x] 01-02: Freeze and implement the control-plane write visibility contract for forwarded writes.
- [x] 01-03: Harden replication ordering and cursor semantics across budget, authority, receipt, and revocation state.
- [x] 01-04: Add failover, convergence, and repeat-run coverage that proves the cluster is stable under load.

### Phase 2: E12 Security Boundary Completion
**Goal**: Turn negotiated roots into enforced runtime boundaries for filesystem-shaped tools and filesystem-backed resources.
**Depends on**: Phase 1
**Requirements**: [SEC-01, SEC-02, SEC-03, SEC-04]
**Success Criteria** (what must be TRUE):
  1. Filesystem-shaped tool calls outside allowed roots are denied with signed evidence.
  2. Filesystem-backed resource reads outside allowed roots are denied with signed evidence.
  3. Root normalization rules are explicit and consistent across the supported transports.
  4. Missing or stale roots never silently expand access.
**Plans**: 4 plans

Plans:
- [ ] 02-01: Freeze the root normalization model and threat boundaries for filesystem-shaped access.
- [ ] 02-02: Enforce roots for tool calls with path-bearing arguments and fail-closed receipts.
- [ ] 02-03: Enforce roots for filesystem-backed resources while preserving non-filesystem resource behavior.
- [ ] 02-04: Add cross-transport tests and docs that make the enforced boundary explicit.

### Phase 3: E10 Remote Runtime Hardening
**Goal**: Make the hosted remote MCP runtime reconnect-safe, resumable where intended, and scalable beyond the current subprocess ownership shape.
**Depends on**: Phase 2
**Requirements**: [REM-01, REM-02, REM-03, REM-04]
**Success Criteria** (what must be TRUE):
  1. Remote sessions follow one documented reconnect and resume contract.
  2. GET-based SSE coverage exists and works against the compatibility surface.
  3. Stale-session cleanup, drain, and shutdown behavior are deterministic and test-covered.
  4. Hosted runtime ownership no longer depends on one subprocess per session in all serious deployments.
**Plans**: 4 plans

Plans:
- [ ] 03-01: Specify resumability, reconnect rules, and terminal states for remote sessions.
- [ ] 03-02: Implement GET/SSE stream support and align POST/GET stream ownership behavior.
- [ ] 03-03: Expand the hosted ownership model for wrapped and native providers.
- [ ] 03-04: Add lifecycle diagnostics, cleanup behavior, and operational docs for hosted runtime use.

### Phase 4: E11 Cross-Transport Concurrency Semantics
**Goal**: Make task ownership, stream ownership, cancellation, and late async completion behave the same way across direct, wrapped, stdio, and remote paths.
**Depends on**: Phase 3
**Requirements**: [CON-01, CON-02, CON-03, CON-04]
**Success Criteria** (what must be TRUE):
  1. One ownership model describes active work, stream emission, and terminal state across transports.
  2. `tasks-cancel` no longer remains `xfail` in the remote story.
  3. Late async completion no longer depends on request-local bridges surviving accidentally.
  4. Cancellation races produce deterministic receipts and terminal outcomes across all supported paths.
**Plans**: 4 plans

Plans:
- [ ] 04-01: Freeze the transport-neutral ownership state machine for work, streams, and terminal state.
- [ ] 04-02: Remove transport-specific task lifecycle edge cases, including the remote `tasks-cancel` gap.
- [ ] 04-03: Normalize cancellation race semantics and nested parent/child linkage.
- [ ] 04-04: Add durable async completion sources and late-event coverage for native and wrapped paths.

### Phase 5: E13 Policy and Adoption Unification
**Goal**: Give operators and adopters one clear policy story and one higher-level path into native PACT services.
**Depends on**: Phase 4
**Requirements**: [POL-01, POL-02, POL-03, POL-04]
**Success Criteria** (what must be TRUE):
  1. One policy authoring path is clearly documented as canonical.
  2. All shipped guards are reachable through the supported configuration surface.
  3. Wrapped-MCP-to-native migration guidance and examples are maintained and evidence-backed.
  4. At least one higher-level native authoring surface exists and is test-covered.
**Plans**: 4 plans

Plans:
- [ ] 05-01: Freeze the supported policy contract and align README, CLI messaging, and docs around it.
- [ ] 05-02: Expose the full shipped guard surface through the supported path with regression coverage.
- [ ] 05-03: Ship migration guides and examples for wrapped-to-native adoption.
- [ ] 05-04: Add a higher-level native authoring surface that covers the core PACT primitives coherently.

### Phase 6: E14 Hardening and Release Candidate
**Goal**: Turn the closing-cycle epics into a release candidate with explicit guarantees, limits, and go/no-go evidence.
**Depends on**: Phase 5
**Requirements**: [REL-01, REL-02, REL-03, REL-04]
**Success Criteria** (what must be TRUE):
  1. Workspace build, lint, and test gates are repeatable in CI and local qualification runs.
  2. Failure-mode, limits, and guarantee docs accurately describe the supported surface.
  3. Examples, conformance coverage, and release docs tell one coherent story.
  4. No remaining post-review finding is deferred into an undefined hardening bucket.
**Plans**: 4 plans

Plans:
- [ ] 06-01: Build the release qualification matrix covering gates, limits, and unresolved findings.
- [ ] 06-02: Add failure-mode, regression, and qualification coverage for the final supported surface.
- [ ] 06-03: Publish release docs covering guarantees, non-goals, migration path, and extension policy.
- [ ] 06-04: Run the final milestone audit and capture the release-candidate go/no-go decision.

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. E9 HA Trust-Control Reliability | 4/4 | Complete | 2026-03-19 |
| 2. E12 Security Boundary Completion | 0/4 | Not started | - |
| 3. E10 Remote Runtime Hardening | 0/4 | Not started | - |
| 4. E11 Cross-Transport Concurrency Semantics | 0/4 | Not started | - |
| 5. E13 Policy and Adoption Unification | 0/4 | Not started | - |
| 6. E14 Hardening and Release Candidate | 0/4 | Not started | - |
