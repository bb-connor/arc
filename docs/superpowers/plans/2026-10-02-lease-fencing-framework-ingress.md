# Lease fencing and framework ingress implementation plan

> Use the execution-plan workflow, with one independent CA3 domain delegate and
> one integrated final review. Root owns AC4, serialized Cargo, evidence and Git.

**Goal:** close AC4 protected-write fencing and CA3 missing ingress coverage at
production consumers.

**Architecture:** explicit lease authority, store-owned time and transactional
SQLite mutations; original-byte HTTP preflight and an expanded classified census.
**Tech stack:** Rust, rusqlite, Axum, Python source gates.
**Spec:** [approved design](../specs/2026-10-02-lease-fencing-framework-ingress-design.md).
**Base:** `14ce46a3edbf75c27162d2c13c1dce07b919b070`.

## AC4

- [x] Reproduce stale run/step/evidence writes, exact expiry and ignored clock failure
  through `chio-runtime-core` SQLite public APIs; retain zero-write snapshots.
- [x] Add insert-only pending registration. Require `&RuntimeRunLease` on every
  protected writer; compare current identity/token/state/expiry under IMMEDIATE
  transaction after owned-clock observation. Keep destructive step evidence
  separate from run ownership. Failed mutation rolls back heartbeat and data.
- [x] Add atomic run/step/evidence progress and fenced one-shot release; migrate the
  `chio-runtime` wrapper, CLI orchestration and affected fixtures. Current lease
  acquisition must not reuse another owner's token.
- [x] Verify reopen, competing handles, stale clock hints, identity substitution,
  malformed persistent lease fields, default-run escape, rollback and actual CLI
  plan/run behavior. Run owner tests and warnings-denied lint.

Files: `crates/kernel/chio-runtime-core/src/store/sqlite/{runs_steps,leases_scheduler}.rs`,
new focused write-fence module/tests, `crates/kernel/chio-runtime/src/stores.rs`,
and `crates/products/chio-cli/src/cli/chio/dispatch/runtime/orchestration.rs`.

## CA3

- [x] Reproduce missing Json/Form, response `.json()`, alternate-format and shared
  reader consumer observations with source-gate tests, excluding response values.
- [x] Build the live inventory with truthful semantic dispositions and bounded
  classifications. Do not expand the raw-input or other debt baselines.
- [x] Add actual-router behavioral RED for original-byte duplicate/numeric/body
  handling; implement bounded original-body preflight for signed/authoritative
  routes while preserving unsigned document decimals and existing route limits.
- [x] Verify nested signed types, honest success, authentication/signature
  validation, rejection without mutation, limits and route composition. Run
  affected control-plane tests and source-gate tests.

Files: `scripts/check-trust-boundaries.py` and focused census helpers/tests,
`docs/security/trust-boundary-inventory.json`, the control-plane router/ingress
owner and production-route regression tests. The CA3 owner records the exact
disposition artifact and route/type coverage.

## Integration and handoff

- [x] Inspect integrated diff with one independent reviewer; fix consequential
  findings with reproducing controls, preserving failed evidence.
- [x] Run changed owner suites, strict Clippy, formatting and affected source
  gates. Retain exact commands, exits, hashes and source/binary identities.
- [ ] Reconcile each finding with its roadmap owner, commit and push authorized
  security source and documentation, and verify remote SHA. Propose the next
  substantial chunk from the remaining live plans/reviews.

Review focus: alternate public writer escape paths; stale authority renewed by
reading current tokens; expiry while waiting for a database lock; shared decoder
alias/helper evasions; route layers that omit preflight or narrow legitimate
numeric/body-limit behavior. Tests and review must cover each condition.
