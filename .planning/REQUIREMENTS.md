# Requirements: PACT

**Defined:** 2026-03-19
**Core Value:** PACT must provide deterministic, least-privilege agent access with auditable outcomes across local and remote deployments.

## v1 Requirements

### Deterministic Trust Control

- [x] **HA-01**: Repeated `cargo test --workspace` runs complete without trust-cluster flakes.
- [x] **HA-02**: Forwarded trust-control writes have one documented read-after-write visibility contract.
- [x] **HA-03**: Budget, authority, receipt, and revocation replication remain correct across leader failover.
- [x] **HA-04**: Cluster diagnostics expose leader identity, cursor/convergence state, and replication failures clearly enough to debug production issues.

### Security Boundary Enforcement

- [ ] **SEC-01**: Roots are normalized consistently across supported transports and platforms for filesystem-shaped access.
- [ ] **SEC-02**: Filesystem-shaped tool access outside allowed roots fails closed with signed evidence.
- [ ] **SEC-03**: Filesystem-backed resource reads outside allowed roots fail closed with signed evidence.
- [ ] **SEC-04**: Missing, empty, or stale roots never silently widen access.

### Remote Runtime Hardening

- [ ] **REM-01**: Remote sessions support one documented reconnect and resume contract.
- [ ] **REM-02**: GET-based SSE streaming is available where the compatibility surface expects it.
- [ ] **REM-03**: Stale-session cleanup, drain, and shutdown behavior are deterministic and tested.
- [ ] **REM-04**: Hosted runtime ownership can scale beyond one subprocess per remote session.

### Cross-Transport Concurrency

- [ ] **CON-01**: One transport-neutral ownership model defines active work, stream emission, and terminal state updates.
- [ ] **CON-02**: `tasks-cancel` passes in the remote conformance story instead of remaining `xfail`.
- [ ] **CON-03**: Late async completions and notifications are durable and session-owned, not request-local accidents.
- [ ] **CON-04**: Cancellation races produce deterministic receipts and terminal states across direct, wrapped, and remote paths.

### Policy and Adoption

- [ ] **POL-01**: One canonical policy authoring path is explicitly documented for operators.
- [ ] **POL-02**: All shipped guards are configurable through the supported policy path.
- [ ] **POL-03**: Wrapped-MCP-to-native migration guidance and maintained examples exist.
- [ ] **POL-04**: A higher-level native authoring surface exists and is covered by tests and examples.

### Release Qualification

- [ ] **REL-01**: Workspace build, lint, and test gates are green in CI and repeat locally.
- [ ] **REL-02**: Supported guarantees, limits, and explicit non-goals are documented for operators and adopters.
- [ ] **REL-03**: Failure-mode, conformance, and example coverage back the claims made in release docs.
- [ ] **REL-04**: No post-review closing finding remains unowned or relegated to an undefined hardening bucket.

## v2 Requirements

### Distributed Control and Sandboxing

- **FUT-01**: Support a stronger distributed-control model than the current HA leader/follower design.
- **FUT-02**: Add deeper sandbox orchestration beyond root-aware filesystem boundaries.
- **FUT-03**: Complete the stronger formal/theorem-prover artifacts described in the draft protocol.

### Extended Platform Surface

- **FUT-04**: Expand identity-provider and token-exchange federation beyond the current hosted-runtime needs.
- **FUT-05**: Add large-scale performance optimization once semantic stability and operator clarity are complete.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Multi-region consensus trust plane | Not required to close current release blockers; would turn the milestone into a new distributed-systems program |
| Full OS sandbox manager | The immediate security gap is roots enforcement, not a general sandbox product |
| Theorem-prover completion | Valuable research work, but not the next blocker for shipping an operational release candidate |
| Performance-first rewrite | Current risks are determinism, security boundaries, and product-surface coherence |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| HA-01 | Phase 1 | Complete |
| HA-02 | Phase 1 | Complete |
| HA-03 | Phase 1 | Complete |
| HA-04 | Phase 1 | Complete |
| SEC-01 | Phase 2 | Pending |
| SEC-02 | Phase 2 | Pending |
| SEC-03 | Phase 2 | Pending |
| SEC-04 | Phase 2 | Pending |
| REM-01 | Phase 3 | Pending |
| REM-02 | Phase 3 | Pending |
| REM-03 | Phase 3 | Pending |
| REM-04 | Phase 3 | Pending |
| CON-01 | Phase 4 | Pending |
| CON-02 | Phase 4 | Pending |
| CON-03 | Phase 4 | Pending |
| CON-04 | Phase 4 | Pending |
| POL-01 | Phase 5 | Pending |
| POL-02 | Phase 5 | Pending |
| POL-03 | Phase 5 | Pending |
| POL-04 | Phase 5 | Pending |
| REL-01 | Phase 6 | Pending |
| REL-02 | Phase 6 | Pending |
| REL-03 | Phase 6 | Pending |
| REL-04 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 24 total
- Mapped to phases: 24
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-19*
*Last updated: 2026-03-19 after reconciling closing-cycle epics into the GSD roadmap*
