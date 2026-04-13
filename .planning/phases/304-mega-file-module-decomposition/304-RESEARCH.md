# Phase 304: Mega-File Module Decomposition - Research

**Researched:** 2026-04-13
**Domain:** Rust module decomposition, file-size hygiene, compatibility-preserving refactors
**Confidence:** HIGH

<phase_alignment>
## Phase Alignment

Phase 304 is the structural cleanup wave that must capitalize on phase 303's
crate boundaries without changing ARC behavior. It must make later phases
easier:

- `305` depends on a decomposed `arc-kernel` before migrating to async `&self`
- `306` depends on clearer dependency surfaces and smaller modules for feature
  gating
- `307+` benefit from a CLI that is no longer trapped in 10K-20K line files

The phase therefore needs two properties:

1. **real internal boundaries** in the largest files, not cosmetic slicing
2. **no external behavior change** while those files become maintainable

</phase_alignment>

<user_constraints>
## Locked Constraints

- No public API or CLI behavior change in this phase
- No protocol semantics, receipt formats, or trust-control route contracts
  should change
- The phase is structural only: module boundaries, dispatch cleanup, and
  file-size reduction
- The end state must satisfy the global file-size gate:
  `find crates/ -name '*.rs' ! -path '*/tests/*' | xargs wc -l | awk '$1 > 3000'`
  returns no results

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| DECOMP-05 | `trust_control.rs` is decomposed into focused modules | The file already exposes clear seams: service state, HTTP DTOs, registry/config helpers, passport/OID4VP flows, federation/SCIM helpers, public-registry helpers, remote-store builders, and cluster sync. |
| DECOMP-06 | `arc-kernel/src/lib.rs` is split so tests and kernel subsystems live in dedicated modules | The crate already has many subsystem files; `lib.rs` is acting as an oversized entrypoint/re-export/test host rather than a true implementation root. |
| DECOMP-07 | `arc-cli/src/main.rs` becomes a thin dispatch entry point with per-subcommand modules | The file already has adjacent command files under `src/`; the oversized root is mostly enum declarations plus `cmd_*` handlers. |
| DECOMP-08 | `receipt_store.rs` and `runtime.rs` are decomposed into focused modules | `receipt_store.rs` mixes persistence, workflow query/reporting, reconciliation, label helpers, and tests. `runtime.rs` already has one extracted `protocol.rs` and still concentrates task handling, transport, and runtime orchestration in one file. |
| DECOMP-09 | No non-test file under `crates/` exceeds 3,000 lines | The global size gate currently also pulls in `arc-mercury/src/commands.rs`, `arc-cli/src/remote_mcp.rs`, and `arc-credit/src/lib.rs`, so phase 304 cannot stop at only the roadmap-named files. |

</phase_requirements>

## Current State

### Oversized non-test files after phase 303

Current scan:

```text
21082 crates/arc-cli/src/trust_control.rs
11788 crates/arc-kernel/src/lib.rs
10387 crates/arc-cli/src/main.rs
9861 crates/arc-store-sqlite/src/receipt_store.rs
7339 crates/arc-mercury/src/commands.rs
7192 crates/arc-cli/src/remote_mcp.rs
6483 crates/arc-mcp-edge/src/runtime.rs
3039 crates/arc-credit/src/lib.rs
```

Implication: the roadmap-named targets are the core of the phase, but DECOMP-09
also forces cleanup of at least three auxiliary files.

### 1. `trust_control.rs` already has natural extraction seams

The current `crates/arc-cli/src/trust_control.rs` file groups several distinct
lanes:

- trust service state, peer health, and cluster replication types
- HTTP request/response DTOs for cluster, budget, revocation, and receipt APIs
- config-path and registry-loading helpers
- public listing and certification helpers
- passport/OID4VP, verifier, and public discovery flows
- SCIM helpers
- remote trust-store builders and HTTP client helpers
- cluster synchronization and consensus helpers

There is already one extracted sibling:
`crates/arc-cli/src/trust_control/health.rs`.

Research conclusion: this file should become a `trust_control/` module tree with
the current file reduced to the public entrypoint and re-export shell.

### 2. `arc-cli/src/main.rs` is an oversized command registry + dispatcher

`main.rs` currently holds:

- top-level CLI structs and command enums
- nested trust/passport/certify/reputation command trees
- `cmd_*` handlers for many unrelated command families
- stub test helpers near the bottom

But the crate already contains adjacent command-family files:

- `admin.rs`
- `did.rs`
- `passport.rs`
- `policy.rs`
- `reputation.rs`
- `federation_policy.rs`
- `scim_lifecycle.rs`
- `remote_mcp/`

Research conclusion: `main.rs` should become a thin root that declares the CLI
types, delegates into per-command modules, and leaves large command-family
implementations outside the entrypoint.

### 3. `arc-kernel/src/lib.rs` is mostly aggregation and tests now

The kernel crate already has dedicated subsystem files:

- `authority.rs`
- `budget_store.rs`
- `checkpoint.rs`
- `payment.rs`
- `receipt_store.rs`
- `runtime.rs`
- `session.rs`
- `transport.rs`
- and others

But `lib.rs` still contains:

- the main crate-level imports and type re-exports
- core helper types and request/receipt plumbing
- the very large `tests` module

Research conclusion: the kernel root should stay as a thin crate root plus a
small coordination layer, while tests and any remaining subsystem logic move to
dedicated modules under `src/`.

### 4. `receipt_store.rs` is multiple subsystems in one file

`crates/arc-store-sqlite/src/receipt_store.rs` currently mixes:

- SQLite schema/open/init
- underwriting, credit, liability, and federated evidence persistence flows
- checkpoint/archive methods
- analytics/reporting queries
- metered billing and settlement reconciliation
- label/parse helper functions
- tests

The surrounding crate already has separate files for authority, budget store,
capability lineage, evidence export, receipt query, and revocation store.

Research conclusion: `receipt_store.rs` should split into a `receipt_store/`
module tree at least across persistence workflows, reporting/reconciliation,
helper/parsing logic, and tests.

### 5. `arc-mcp-edge/src/runtime.rs` is ready for module extraction

This file already extracted `runtime/protocol.rs`, which is the strongest sign
that further decomposition is expected. The remaining file still holds:

- task state and task-final-outcome types
- nested-flow client helpers
- request/notification handling
- background task processing
- JSON-RPC transport loops
- tests

Research conclusion: split `runtime.rs` into a `runtime/` module tree around
state types, request/notification handling, tool execution/task processing, and
tests, with the current `runtime.rs` either deleted or reduced to a small
facade module.

### 6. Auxiliary size-gate files need one cleanup wave

Even if the roadmap-named files are split, DECOMP-09 still fails unless these
are handled:

- `crates/arc-mercury/src/commands.rs` — 7,339 lines
- `crates/arc-cli/src/remote_mcp.rs` — 7,192 lines
- `crates/arc-credit/src/lib.rs` — 3,039 lines

These are likely best handled in a final cleanup wave after the main
decomposition work lands, because:

- `remote_mcp.rs` is already adjacent to `remote_mcp/admin.rs`
- `commands.rs` is a product CLI command surface similar to the main CLI split
- `arc-credit/src/lib.rs` only needs to drop slightly below the hard threshold

## Recommended Cut

### Plan 01: Decompose the ARC CLI mega-files

Scope:

- `crates/arc-cli/src/trust_control.rs`
- `crates/arc-cli/src/main.rs`
- `crates/arc-cli/src/remote_mcp.rs`

Reasoning:

- These files live in the same crate and can share a consistent decomposition
  pattern
- `trust_control.rs` and `main.rs` are the two largest files in the repo
- `remote_mcp.rs` is already part of the same CLI surface and is required for
  DECOMP-09 anyway

### Plan 02: Decompose kernel, MCP runtime, and SQLite receipt-store roots

Scope:

- `crates/arc-kernel/src/lib.rs`
- `crates/arc-store-sqlite/src/receipt_store.rs`
- `crates/arc-mcp-edge/src/runtime.rs`

Reasoning:

- These are the central runtime/persistence mega-files called out in the
  roadmap
- They already sit inside crates with surrounding subsystem files, which lowers
  extraction risk
- This plan directly unblocks phase 305's async kernel work

### Plan 03: Finish the size gate and prove compile/test stability

Scope:

- `crates/arc-mercury/src/commands.rs`
- `crates/arc-credit/src/lib.rs`
- any remaining >3000-line non-test file after plans 01-02
- final global size gate and targeted compile/test verification

Reasoning:

- DECOMP-09 is global, so phase 304 needs an explicit final cleanup wave
- This plan should also own the no-regression proof after the major file moves

## Validation Architecture

### Quick validation loop

For fast feedback during decomposition:

```bash
cargo check -p arc-cli -p arc-kernel -p arc-store-sqlite -p arc-mcp-edge
```

### CLI-focused validation

After CLI file moves:

```bash
cargo check -p arc-cli -p arc-control-plane -p arc-hosted-mcp -p arc-mercury
```

### Runtime-focused validation

After kernel/store/runtime file moves:

```bash
cargo check -p arc-kernel -p arc-store-sqlite -p arc-mcp-edge -p arc-settle -p arc-wall
```

### Final phase verification

Before phase completion:

```bash
cargo check --workspace
cargo test -p arc-cli -p arc-kernel -p arc-store-sqlite -p arc-mcp-edge --tests
find crates -name '*.rs' ! -path '*/tests/*' -print0 | xargs -0 wc -l | awk '$1 > 3000'
```

## Risks and Mitigations

### Risk 1: public entrypoints accidentally change

Mitigation:

- keep thin top-level facades
- re-export or delegate instead of renaming public types/functions
- validate with crate-level compile checks and existing tests

### Risk 2: file splits create circular module dependencies

Mitigation:

- split by domain/responsibility, not arbitrary line count
- prefer internal helper modules over broad cross-imports
- keep root files as coordination layers only

### Risk 3: DECOMP-09 fails even after roadmap-named files are fixed

Mitigation:

- treat `remote_mcp.rs`, `arc-mercury/src/commands.rs`, and `arc-credit/src/lib.rs`
  as first-class phase scope
- run the global size gate after each plan wave, not only at the end

### Risk 4: kernel async migration gets harder if 304 overfits structure

Mitigation:

- keep decomposition aligned to subsystem seams phase 305 will likely need:
  request handling, session flow, receipt creation, runtime dispatch, and tests
- avoid rewriting behavior or signatures in phase 304
