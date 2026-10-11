# PR sprawl containment implementation plan

> **For agentic workers:** Use `superpowers:executing-plans` inline. The user
> prohibits subagents. Existing authorization covers the described PR updates,
> protected merges, commits and pushes.

**Goal:** Consolidate duplicate PRs without abandoning valuable work, maintain an
exact landing ledger, and qualify and merge the process/security foundation.

**Architecture:** Preserve published histories and transfer each original review
obligation to an explicit surviving candidate. Keep unique valuable work open
until completed and merged. Use the existing integration worktree and qualify
the final source with the existing protected checks and native trust boundaries.

**Tech Stack:** Git, GitHub REST/GraphQL, Python audit tooling, Rust workspace and
its existing native, formal and hosted qualification workflows.

**Spec:** The user's four-step execution request and subsequent preservation
constraint, `docs/security/landing-ledger.md`, and
`docs/security/foundation-acceptance-scope.md`.

## Global constraints

- No subagents, branch deletion, force pushes or qualification bypasses.
- No feature is dropped or placed in closed backlog to reduce a count.
- A duplicate PR may close only after its complete source and review obligations
  are preserved in a named surviving candidate. Closure is not a merge claim.
- Refresh exact heads, bases and all review threads before mutations.
- At most two active landing candidates. Other useful tracks retain named open
  destinations and explicit remaining acceptance.
- Search existing security branches and source repair records before changing
  behavior. Keep genuine source audits and fail-closed enforcement intact.
- Retain failed, cancelled, unavailable and partial evidence distinctly.
- No em dashes in code or documentation.

## Review focus

- Changed heads or new review comments invalidate stale retirement decisions.
- Patch equivalence must cover every absent commit, not only the last patch.
- A surviving child must not lose its base or acquire unrelated source silently.
- Code preservation does not establish that review findings have been repaired.
- Source changes invalidate exact-candidate qualification; a green local subset
  cannot establish native, hosted, independent review or merge acceptance.

### Task 1: Consolidate the 57 process/security duplicates

**Files:** Update `docs/security/landing-ledger.{json,md}`; create
`docs/security/pr-consolidation-20261004.json` and a compact retained review
snapshot under `docs/security/audits/`.

**Interfaces:** Consumes current PR heads, full review threads, the existing
retirement manifest and source histories. Produces a published source/review
transfer record and one recorded GitHub outcome per candidate.

- [x] Refresh the open inventory, review threads and published refs; refuse any
  unexplained drift or incomplete pagination.
- [x] Verify 54 original heads through ancestry and all absent commits of the
  other three through exact patch/blob equivalence and published archives.
- [x] Preserve every live review obligation in the ledger; retain original
  thread bodies and resolution states without marking them repaired by closure.
- [x] Retarget #1155 to the surviving foundation branch and verify its unique
  change remains intact.
- [x] Publish the transfer record, then close duplicates in child-before-parent
  order with exact source and review links. Preserve all branches and archives.
- [x] Verify the resulting 28 open PRs, source refs and closure outcomes.

### Task 2: Consolidate the workbench stack into #1164

**Files:** Extend the same consolidation record and ledger; update #1164's
description with its expanded scope, inherited review obligations and open
acceptance.

**Interfaces:** Consumes the six older workbench heads and review records.
Produces one surviving workbench candidate, separate from foundation acceptance.

- [x] Verify #1164 contains all six complete older heads and refresh reviews.
- [x] Transfer each original review obligation and inherited feature to #1164.
- [x] Retarget #1164 to main, verify the expanded diff, then close the six older
  PRs as superseded while keeping their branches.
- [x] Verify the resulting 22 open PRs and all preserved source refs.

### Task 3: Account for all remaining valuable work

**Files:** Update the authoritative ledger and consolidation record.

**Interfaces:** Consumes the 22 surviving PRs and current main/foundation source.
Produces explicit landing destinations, dependency order and remaining acceptance.

- [x] Give every survivor a named open destination or an active landing slot.
- [x] Keep #1155 and #1136's unique changes accounted for and open.
- [ ] Reconcile #1029 and other legacy changes against main and the security
  histories by requirement and patch; do not retire unmatched valuable source.
- [x] Verify every PR appears exactly once and no useful track is closed merely
  because it is outside the active two-PR queue.

### Task 4: Repair and qualify the foundation

**Files:** Only the owning source/tests or qualification definitions identified
by current failures; record exact repairs and evidence in the landing ledger.

**Interfaces:** Consumes final candidate failures and the seven existing review
slices. Produces reviewed source, terminal hosted/native evidence, and a protected
foundation merge with post-merge source verification.

- [ ] Retrieve current failed job logs and reproduce each root cause; search
  existing repairs before writing new code.
- [ ] For each behavioral repair, first demonstrate the failure with an owning
  regression, then implement the smallest modular repair and rerun the relevant
  suite and owning Clippy checks.
- [ ] Complete dependency-ordered source review and reconcile every finding.
- [ ] Obtain independent review of the exact final source without subagents.
- [ ] Complete the required native mutation campaigns and trusted capture chain
  under their existing isolation and acceptance rules.
- [ ] Obtain terminal passing required checks for the exact candidate, merge
  through protection, and verify the actual main ancestry and remaining ledger.

## Qualification findings from this execution

- #1136 is already carried by exact patch equivalence at
  `1898aa9d5fb0a0be486b9f1d3b439ac1049405fa`. Preserve its original native
  macOS evidence and verify the eventual landing; do not reimplement its repair.
- #1029 retains 219 distinct non-merge patches and all 78 original review
  threads. Its explicit open destination satisfies containment. Semantic
  reconciliation remains a prerequisite to its later consolidation or landing.
- The PostgreSQL native demo opens a direct database connection before tool
  discovery, but the enforced cage denies socket creation and connection. The
  workflow now supplies the missing enforcement fixture, but a mediated
  database integration still needs design, source and native qualification.
  Preserve the profile, required checks and useful demo source.
- The current local host and Docker daemon are ARM64. The required trusted
  Linux x86_64 campaign and hosted provenance remain separate acceptance.
- Mobile source wrappers now match the current FFI. The rebuilt Apple framework
  and committed package pass the native Swift checks on `69435a1a5b`. The supported
  Kotlin consumer matrix and final foundation qualification remain open;
  TypeScript and host Rust FFI results cannot replace them.

## Independent review follow-up (October 5)

Use the user-authorized GitHub Codex review integration. Its completed review of
`19df31ad93a91bcb4d984094df375100935bbdf3` reports two P1 findings in
[comment 5986409195](https://github.com/bb-connor/arc/pull/1160#issuecomment-5986409195).
Neither a completed review with findings nor a self-authored repair reply is approval.

- [x] Reproduce all three weak FROST transport boundaries, reject provisioned
  weak keys, and use strict verification in both rounds. Commit `d0e88d93f1`
  passes 23 authority tests; the one ignored test regenerates fixtures and is
  deliberately not executed. All-target Clippy passes with warnings denied.
- [x] Recheck the archive finding against the actual source. Commit `58cc1b55bc`
  already supplies authenticated, read-only schema-6 compatibility. All 16
  checkpoint/writer boundary tests pass, including a new repeated-rotation test.
  Do not duplicate that migration or rewrite operator-owned archives at startup.
- [x] Regenerate proof coverage and both stale deployment dependency graphs.
  Locked fork reconstruction and deployment resolution, Cargo Vet and the
  generated coverage check pass locally without added exemptions.
- [x] Require successful native Swift-to-Rust calls in the SDK tests. The former
  test incorrectly accepted `bindingUnavailable` as success. Native run
  `37251015566` fails all three Rust consumer tests with that error, while both
  App Attest wrapper tests pass. Preserve this red result separately.
- [x] Use the workspace-locked UniFFI generator, build the Apple static
  libraries, expose their C module correctly, and compile generated Swift as
  a real package target. Rebuild the bundled framework and test that exact SDK.
- [ ] Preserve native build provenance, renew final independent review and
  complete hosted, Linux/native/trusted and protected-merge acceptance.

The rebuilt SDK from `60ec98d6fd` passes all five native tests in run
`37252196996`, job `111582101361`; the artifact's exact ZIP and installed-file
hashes are retained. Source `6428fac61a` installs that tested bundle. The old
committed-package job failed separately, so the run remains failed. The committed
package and push rebuild later pass on `69435a1a5b` in runs `37254058490` and
`37254049495`. That source also receives a completed Codex review reporting no
major issues, without a formal GitHub approval or final foundation qualification.

The independent review of `60ec98d6fd` adds two P1 obligations. Source
`6428fac61a` expands Swift triggers to all local Rust sources and rejects weak
MCP sender keys, using strict DPoP and JWT signatures. Four attack controls fail
before repair; all 137 owning tests and all-target Clippy pass afterward.
Independent rereview and foundation qualification remain open.

Six source comparisons for #1029 are recorded in
`docs/security/legacy-integration-reconciliation-20261005.json`. They identify
current cumulative-approval and retry owners while retaining unresolved
transcript and credit-path composition obligations. This is a partial semantic
comparison, with all unmatched valuable source still open.

The adjacent authority audit then reproduces five weak-key failures in kernel
DPoP and broker proofs. Repair `75f2a51c9d` passes 84 kernel DPoP tests, all 177
broker library tests, owning all-target Clippy and structural proof checks.
Repair `dad90af0fc` supplies the missing qualified fixture and enforcing CLI
to SDK parity. Its reproduced contract failure passes with all 13 hostile
workflow-contract methods afterward. Both repairs need fresh independent review
and exact-candidate hosted/native qualification.

## Execution rulings

- The user's later preservation instruction supersedes the earlier proposal to
  close deferred valuable work into backlog. Only duplicate PR containers close;
  their work continues in the surviving candidate until qualified and merged.
- The earlier manifest's requirement to merge #1160 before closing any duplicate
  is replaced by the user's explicit pre-merge supersession authorization.
  Published preservation and transferred obligations remain mandatory.
- The existing integration worktree is clean and already isolated. Baseline CI
  is known to fail; diagnosis and repair are explicitly authorized, so no fresh
  worktree, broad baseline rebuild or additional permission cycle is needed.
