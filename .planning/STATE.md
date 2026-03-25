---
gsd_state_version: 1.0
milestone: none
milestone_name: none
status: ready_for_new_milestone
stopped_at: `v2.4` archived; next clean step is to define or activate `v2.5`
last_updated: "2026-03-25T20:35:31Z"
last_activity: 2026-03-25 -- archived `v2.4` after passing all four architecture refactor phases
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-25)

**Core value:** PACT must provide deterministic, least-privilege agent access
with auditable outcomes, and produce cryptographic proof artifacts that enable
economic metering, regulatory compliance, and portable trust across
organizational boundaries.
**Current focus:** Define the next milestone on top of the archived `v2.4`
architecture baseline

## Current Position

Phase: none
Plan: none
Status: No active milestone; `v2.4` is archived and `v2.5` is next planned
Last activity: 2026-03-25 -- archived `v2.4` after passing all four
architecture refactor phases

Progress: [----------] awaiting next milestone

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans, plus substantial post-milestone
  portable-trust execution beyond the original archive
- v2.1: complete (15/15 plans)
- v2.2: complete (12/12 plans executed)
- v2.3: complete and archived (12/12 plans executed)
- v2.4: complete and archived (12/12 plans executed)

## Accumulated Context

### Decisions

- Imported federated evidence remains isolated from native local receipt tables;
  foreign receipts are not mixed into local receipt history.
- Multi-hop federated lineage uses explicit bridge records rather than foreign
  parent references in native local lineage tables.
- Shared remote evidence is now operator-visible through reference reports
  rather than direct foreign receipt ingestion.
- Portable verifier policies now ship as signed reusable artifacts with
  registry-backed references and replay-safe verifier challenge persistence.
- Passport verification, evaluation, and presentation now support truthful
  multi-issuer bundles for one subject without inventing aggregate cross-issuer
  scores.
- Identity federation now supports provider-admin, SCIM, SAML, and
  policy-visible enterprise identity context.
- A2A partner hardening now includes explicit request shaping, fail-closed
  partner admission, and a durable task registry for restart-safe follow-up
  recovery.
- Certification artifacts now support local and remote registry publication,
  resolution, supersession, and revocation.
- v2.3 began with release hygiene and maintainability work rather than another
  feature wave.
- `cargo fmt`, `cargo clippy`, and `cargo test --workspace` remain hard release
  gates.
- Release inputs now fail closed on tracked generated Python/package artifacts
  through `scripts/check-release-inputs.sh`.
- Provider admin, certification, and federated issuance CLI handlers now live
  in `crates/pact-cli/src/admin.rs` instead of staying embedded in `main.rs`.
- Production qualification now has one canonical entrypoint in
  `./scripts/qualify-release.sh`, with dashboard, TypeScript SDK, Python SDK,
  Go SDK, live conformance, and repeat-run trust-cluster proof all included.
- The TypeScript SDK now declares its own build-time dependencies and ships a
  deterministic `package-lock.json` for clean package qualification.
- The `receipt_query` integration harness now retries trust-service startup and
  reports child stderr on early failure so the release lane is stable and
  diagnosable.
- Operator deployment, backup/restore, upgrade, and rollback procedures now
  live in `docs/release/OPERATIONS_RUNBOOK.md`.
- Trust-control `/health` now surfaces authority, store, federation, and
  cluster state in one additive operator contract.
- Hosted MCP edges now expose `/admin/health` with auth, store, session,
  federation, and OAuth summaries.
- `spec/PROTOCOL.md` now describes the shipped `v2` repository profile instead
  of the older pre-RFC draft.
- Release, README, SDK, standards, checklist, and risk docs now align to one
  `v2.3` production-candidate contract.
- `v2.4` is intentionally an architecture milestone rather than the previously
  sketched commercial-trust milestone.
- The flat workspace stays, but new crates will be introduced at the real
  service, storage, and edge boundaries: `pact-control-plane`,
  `pact-hosted-mcp`, `pact-store-sqlite`, and `pact-mcp-edge`.
- Extraction order matters: service boundaries first, then kernel and store,
  adapter boundaries next, and domain-module cleanup last.
- Phase 25 uses compatibility-facade crates first: `pact-control-plane` and
  `pact-hosted-mcp` now own the service boundaries, while path-included modules
  keep the first extraction low-churn before deeper native module cleanup.
- Phase 26 keeps SQLite persistence/query/export code in a dedicated
  `pact-store-sqlite` crate, while `pact-kernel` retains contracts and a
  smaller runtime facade.
- Phase 27 introduced `pact-mcp-edge` as the MCP runtime owner and reduced
  `pact-a2a-adapter/src/lib.rs` to a thin facade over concern-based source
  files.
- Phase 28 reduced `pact-credentials`, `pact-reputation`, and
  `pact-policy/src/evaluate.rs` to thin facades and added a workspace layering
  guardrail plus architecture guide.
- `v2.4` is now archived; `v2.5 Commercial Trust Primitives` remains the next
  planned milestone but has not been activated yet.
- Storage-backed `mcp_serve_http` verification remains reliable when run
  serially; the suite still has a pre-existing parallel port-reservation race.

### Pending Todos

- Resolve historical milestone archive boundaries before attempting
  phase-directory cleanup.
- Define the concrete `v2.5` requirement set before starting the next
  implementation wave.
- Preserve the new compatibility facades while converting the extracted
  service crates into native internal modules over later phases.
- Keep the new layering guardrail narrow and fail-closed as more crates are
  added in future milestones.

### Blockers/Concerns

- Several runtime/domain entrypoints are still too large for comfortable
  ownership, especially `trust_control.rs`, `remote_mcp.rs`,
  `pact-mcp-edge/src/runtime.rs`, and `pact-kernel/src/lib.rs`.
- Future feature work must avoid dependency cycles and avoid turning
  `pact-cli` into another transitively giant shell.
- `pact-control-plane` and `pact-hosted-mcp` currently rely on compatibility
  facades/path-included modules; later phases should normalize those into
  native internal module layouts once the crate boundaries are stable.
- `mcp_serve_http` still uses a port-reservation helper that is flaky under
  heavy parallelism; future test-hardening should remove the need for serial
  verification.
- Formal proof debt and spec/runtime drift still exist and should be treated as
  milestone work, not background assumptions.

## Session Continuity

Last session: 2026-03-25
Stopped at: `v2.4` archived; next clean step is to define or activate `v2.5`
Resume file: None
