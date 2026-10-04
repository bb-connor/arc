# Security and process landing ledger

> Execution owner: use `superpowers:executing-plans` inline, with one independent
> review before each protected landing. This is the authoritative landing order.

**Goal:** Land the qualified process/security foundation on `main`, retire
superseded PRs without losing source or review obligations, and retain an exact
remaining-work ledger.

**Architecture:** Preserve the accumulated branch as an immutable reference.
Land dependency closure and trusted workflow definitions first. Use PR #1160 for
the bounded foundation; qualify subsequent changes in dependency order. Keep at
most two PRs in the active landing queue.

**Tech Stack:** Rust, Cargo Vet/Deny, Python, Git, GitHub Actions and the existing
native Linux qualification and evidence contracts.

**Spec:** The user's October 4 landing directive, the
[launch execution contract](launch-execution-plan.md),
[September completion plan](../superpowers/plans/2026-09-22-security-roadmap-completion.md),
[assurance closeout](../superpowers/plans/2026-09-25-security-assurance-closeout.md)
and their recorded review corrections. This ledger changes sequencing, not the
security acceptance requirements.

## Global constraints

- The preserved source is `ecb44791501c2aba671de2a967d2506f039ab42e`, tagged
  `archive/security-roadmap-pre-landing-20261004`.
- Preserve security history `5d1a9ec0d900bd03ce55de903919d972be852d79` and process
  history `2e84f121273df7f205cc218739b86e93c91bdc37` in the foundation.
- A source repair, local pass, hosted pass, merge and operational acceptance are
  separate states. Historical checkboxes do not establish current qualification.
- Do not exempt the unaudited AWS-LC Rust dependency or weaken required checks.
- Use one Cargo owner per checkout, locked dependencies and `umask 022`. Bind
  `CHIO_CHECKOUT_ROOT` whenever a Cargo target is outside the checkout.
- Do not discard branches, untracked evidence or unique commits. No history
  rewrite is necessary for preservation or PR retirement.
- Workbench, funded-work, research and Mercury proof-feature development remain
  outside this security landing queue. Existing security repairs stay preserved.
- Automatic response remains disabled. A foundation merge is not M10 release or
  M11 pilot acceptance.

## Review focus

1. Missing or duplicate requirements in the ledger must be reported, including
   requirements inherited from review threads and superseded plan prose.
2. A dependency audit must identify exact upstream bytes and the local patch;
   Cargo Vet's registry-version model alone cannot authenticate a path fork.
3. Reduced build contexts and standalone locks must consume the same reviewed
   dependency, and its regression must actually run in CI.
4. A selected older foundation must carry later repairs to boundaries it exposes;
   choosing an old commit is not evidence that it is safe to merge.
5. PR retirement must preserve unique source and unresolved review obligations;
   an ancestor branch closed as superseded is not independently merged.

## Source of truth

The companion `landing-ledger.json` records each requirement's source,
disposition, repair/evidence references, remaining acceptance and landing unit.
It also records the PR ancestry inventory. Status pages link here instead of
maintaining competing continuation queues. Historical reports remain evidence
for their named source only.

The initial inventory contains 1,303 obligation records from 39 source documents:
explicit plan tasks/checklists, named findings, 109 inherited thread dispositions
and nine prerequisite review threads. The October 1 slices account for all 128
execution findings and 69 product/compliance findings. These records overlap by
design and are not 1,303 distinct defects. Uncorroborated historical claims remain
open for source/acceptance reconciliation; no count establishes readiness.
The October 4 prerequisite review adds 14 audit, regression and residual-debt
records: the current inventory is 1,317 records from 45 source documents.

## Active queue

| Order | PR | Responsibility | Acceptance |
| --- | --- | --- | --- |
| 1 | [#1168](https://github.com/bb-connor/arc/pull/1168) | Dependency closure and genuine upstream/fork audit | Review dispositions, exact-source tests, required terminal CI, protected merge |
| 2 | [#1167](https://github.com/bb-connor/arc/pull/1167) | Trusted workflow definitions | Qualified dependency base, complete reviewed definitions, required terminal CI, protected merge |
| Waiting | [#1160](https://github.com/bb-connor/arc/pull/1160) | Bounded process/security foundation | Both histories, required security repairs, independent review, native/trusted evidence, exact-candidate CI |

Later hardening and product-evidence slices receive a PR only when an active
slot becomes available. Their source remains in the preserved reference.

### Task 1: Establish and validate the authoritative ledger

**Files:** `docs/security/landing-ledger.{md,json}`, existing status indexes and
`scripts/check-security-landing-ledger.py`.

**Interfaces:** Consume immutable specifications, execution records and live PR
threads; produce requirement-level dispositions and a bounded landing queue.

- [x] Inventory all requirement sources and inherited review threads.
- [x] Record repairs and evidence without converting historical passes to current
  qualification; explicitly retain unimplemented and unverified requirements.
- [x] Verify coverage, unique identities, source hashes, evidence links and queue
  limits with `python3 scripts/check-security-landing-ledger.py`.
- [x] Update existing status documents and remove competing continuation orders.
- [x] Commit and publish the reconciled ledger (`f6b9203728`).

### Task 2: Repair and land the prerequisites

**Files:** PR #1168's dependency manifests, vendored AWS-LC source/provenance,
audit records, regression and workflow inputs; PR #1167's five workflow files.

**Interfaces:** Consume Task 1's exact source and review IDs; produce reviewed
dependency closure and trusted workflow definitions on `main`.

- [x] Reproduce the Cargo Vet failure and disposition all nine #1168 threads.
- [x] Complete genuine source review and exact fork reconstruction; retain
  failures and run default, FIPS and DES regression qualification.
- [x] Repair confirmed regressions with failing-then-passing checks. Verify
  standalone locks, reduced build contexts and workflow triggers.
- [ ] Obtain an independent review and required terminal checks for #1168's exact
  head, then merge without bypassing protection.
- [ ] Integrate that main base into #1167, qualify its reviewed definitions and
  exact-head checks, then merge without bypassing protection.

### Task 3: Qualify and land the bounded foundation

**Files:** PR #1160's selected foundation and the production/qualification owners
required by its dependency closure.

**Interfaces:** Consume both preserved histories and Task 2's merged main base;
produce a source-pinned qualified foundation on `main`.

- [ ] Select a dependency-ordered cut and map later repairs onto exposed
  boundaries. Preserve all remaining source in the archive reference.
- [ ] Reconcile source, review, native runner, signed capture and CI identities.
- [ ] Run complete foundation acceptance and independent review, repair failures
  without weakening assertions, then require terminal exact-candidate CI.
- [ ] Merge #1160 through protection and verify the resulting main ancestry.

### Task 4: Retire superseded PRs and establish sequential follow-ups

**Files:** The PR disposition inventory, this ledger and affected PR metadata.

**Interfaces:** Consume requirement coverage and proven ancestry from Task 3;
produce fewer open PRs with preserved source and explicit follow-up ownership.

- [ ] Verify each retirement against current heads and transfer every review
  obligation to its replacement record.
- [ ] Retarget surviving dependents, close superseded PRs with replacement links
  and preserve branches containing unique source.
- [ ] Keep at most two PRs active; assign later security slices in dependency
  order and leave unrelated product/research tracks separate.
- [ ] Refresh main/remote/PR identities and report completed and remaining
  requirements with their actual acceptance boundaries.

## Execution record

- October 4: refreshed origin; main remains `f5566d9a765c21cb36652a99c79de64968a656bf`.
  PR #1168 remains `b0dfffb35e5e889d158767e31bfe0d2da1832413`.
  Fresh `cargo vet --locked` exits 255 with exactly one unvetted dependency:
  `aws-lc-rs:1.18.1` missing `safe-to-deploy`.
- Ruling: use the user's explicit execution and landing authorization throughout
  this sequence. Routine skill approval menus do not require another approval.
  Protected checks and genuine audit requirements remain mandatory.
- Ruling: retained raw logs stay outside the source tree; commit concise audit
  reports, exact identities and content hashes. If a required artifact cannot be
  independently retrieved, its public-evidence acceptance remains open.
- October 4 prerequisite candidate: `c5b36bd17bcd4c1189f40285451e30117480c236`
  is committed, pushed and independently source-approved. All nine original
  review threads are resolved. Exact-commit hosted checks and protected merge
  remain pending; main has not moved.
- Genuine AWS-LC review found six partial AES-key initialization sites and an
  invalid private C-string conversion. The fork repairs both and retains DES
  validation. The published registry wrapper is not certified safe to deploy;
  its non-implying review criterion is combined with mandatory authenticated fork
  reconstruction, six deployment graphs, native/transitive audits and tests.
  No Cargo Vet exemption was added.
- Independent review also drove mandatory immutable-source publisher gates,
  build-output isolation, current hosted/formal contracts, static native builder
  dependencies and a disputed-payment regression repair. The original failures
  remain retained. Native default/FIPS/Memcheck and focused repair tests passed.
  Actual aarch64 Alpine builder commands exited zero; 4,379 copied source inputs
  and the Dockerfile match the candidate. This is not full image publication or
  native security-enforcement qualification.
- The npm lock repair removes 23 patchable advisory IDs. Two unpatched
  peer-tooling exceptions expire on October 18 and have independently exercised
  scope/expiry controls. They, three inherited npm exceptions and the inherited
  cpp_demangle baseline audit remain explicit follow-up debt. An effective
  passing scan does not erase the retained raw findings.
- Foundation boundary assessment: retain #1160's lineage and both histories,
  integrate the qualified prerequisites, and project the archive's necessary
  source repairs into dependency-ordered review slices. Bare historical cuts
  omit later custody/authority repairs. RV1-RV5 are mandatory foundation
  obligations because their owners are exposed; they are no longer queued as
  optional follow-ups. The candidate has not yet been constructed or qualified.
- Raw evidence externalization requires dependency analysis. Four evidence
  trees account for 14,770 of the archive's 20,701 changed paths. Required test
  fixtures, exact-source manifests and retrievable evidence must survive a cut.
  The eight `chio-http-serve` paths also need a review-slice owner before the
  broad-diff gate can accept the projection. Existing Mercury security consumer
  repairs remain in scope; new proof development stays in its separate track.
