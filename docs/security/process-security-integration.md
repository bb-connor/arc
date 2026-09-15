# Process and security integration execution plan

> **Execution:** Continue directly with superpowers:executing-plans and focused
> review checkpoints. The user explicitly requested no further subagents.

**Goal:** Preserve the existing process capabilities, reconcile them with the
locally accepted M4 security implementation, qualify the combined foundation,
merge eligible dependency-complete changes, then execute M5 using that foundation.

**Architecture:** `chio-process` owns durable logical process identity,
checkpoints, authenticated worker transport and supervision. The existing kernel
and its qualified durable authority continue to own dispatch, captured budgets,
revocation, receipts and uncertain outcomes. M5 composes these components; neither
a second worker runtime nor a replacement admission coordinator is introduced.

**Tech stack:** Rust 1.94.1, SQLite, Tokio, native MCP, Python/JavaScript worker
SDKs, and the existing Linux enforcement and GitHub qualification machinery.

**Spec:** [Security execution plan](launch-execution-plan.md), especially its
working rules, M2-M4 preservation requirements and complete M5 acceptance. The
user approved this integration-before-M5 order on 2026-09-14.

## Global constraints

- Preserve all M4 source and accepted security behavior from
  `5d1a9ec0d900bd03ce55de903919d972be852d79`.
- Retain the complete process ancestry through PR #1155 at
  `2e84f121273df7f205cc218739b86e93c91bdc37`, including #1131 and #1153/#1154.
  Retention does not mean every inherited application is a launch prerequisite.
- Work only in `/tmp/arc-security-launch`, on `integration/process-security-m4`.
  Keep `security/launch-integration` and all other worktrees intact. Do not force
  push, reset user changes, delete valuable features, or silently close old PRs.
- Fail closed; use canonical JSON for signed artifacts; no new unsafe code
  without necessity and review; deny unwrap/expect; no em dashes; conventional
  commits. Prefer small state-transition helpers over duplicated lifecycle logic.
- Unknown external effects are never retried merely because a worker, container
  attachment, logging operation or cleanup operation failed.
- One implementation owner and one Cargo owner at a time for this worktree.
  Use `umask 022`, `CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`, and no custom
  `RUST_MIN_STACK`. Preserve failures as evidence and fix their owning boundary.
- Never turn an unresolved review thread into a proven bug or a resolved fix
  without checking the actual combined source and regression evidence.
- Merge only after the applicable exact-head tests, required checks and review
  gates pass. User authorization to integrate does not authorize bypassing branch
  protection, repinning trusted execution controllers, publishing or deploying.
- The M1 confinement deferral is not an M5 waiver. Container worker isolation and
  a process-journal call ceiling do not replace native tool confinement or the
  kernel's shared aggregate authority.

## Starting evidence

Read-only preflight found 76 open PRs and 67 drafts. Process work begins at #1098;
#1099 adds authenticated workers and #1104 adds native supervision. #1131 bridges
the process stack to an older security checkpoint. The current security branch
is 32 commits beyond their shared base `8b9f9243905dfa61acac82d83438684940777fe3`.
The merge probe found 13 conflicting paths for #1131, and 14 through #1154.
The existing reference-swarm baseline has three passing tests and remains
integration-only. No current combined implementation or merge is qualified.

## Task 1: Reconcile the complete process ancestry with M4

Checkpoint completed at `deb9b8a85623f7eb4bebd65eeb608af76f11d125`.
Independent specification and quality review approved the reconciliation.
Evidence: both compile checks, 55 process tests, five signed-lineage tests,
29 distinct focused SQLite regressions, mutation-sensitive shared-custody tests,
generated coverage and formatting checks. Source hygiene passes with existing
size warnings. This is not the full-foundation qualification in Task 5.

**Files:** All inherited process changes from the pinned #1155 head. Resolve
conflicts in `.github/workflows/cflite_pr.yml`, kernel `admission_coordinator.rs`,
`tests.rs`, `validation.rs`, `receipt_store.rs`, `runtime.rs`, SQLite
`admission_operation_store.rs`, `admission_operation_store/store.rs`,
`budget_store/composite/transitions/capture.rs`, `lib.rs`, `serving_owner.rs`,
`tool_outcome_store.rs`, `docs/formal/COVERAGE.md`, and
`scripts/check-rust-file-hygiene.py`. Paths are relative to their existing crate
directories. Resolve any additional compiler-proven interface drift at its owner.

**Interfaces:** Preserve current M4 admission commands, runtime replay custody,
caller delivery, retained security contexts and signed terminal projections.
Restore the process branch's signed ancestor verification, process journal,
worker protocols, process ABI v2, recovery claims and capability digest dispatch
attribution. Both complete parent histories must remain reachable.

- [x] Inspect the three-way changes at each conflict, including auto-merged
  admission/terminal code. Record which invariant each resolution preserves.
- [x] Begin the non-destructive merge and inspect unresolved paths:

  ```sh
  git merge --no-ff --no-commit 2e84f121273df7f205cc218739b86e93c91bdc37
  git diff --name-only --diff-filter=U
  ```

- [x] Resolve with `apply_patch`, retaining both behaviors, not blanket ours or
  theirs. For generated proof coverage, merge its source inventories and
  regenerate with `cargo xtask gen proof-coverage` after compilation.
- [x] Capture the first combined compilation failures, then repair precisely the
  incompatible interfaces. Do not disable features, guards or tests to compile:

  ```sh
  cargo check --locked -p chio-process --features worker-server,mailboxes
  cargo check --locked -p chio-cli
  cargo test --locked -p chio-kernel-core --test signed_lineage
  cargo test --locked -p chio-process --features worker-server,mailboxes
  ```

- [x] Verify no conflict markers, whitespace errors or lost ancestry. Commit the
  reconciliation as `feat(process): reconcile durable hosting with M4 security`.
  The commit is an integration checkpoint, not full qualification.
- [x] Review the conflict resolutions and changed security interfaces against
  both parents before proceeding to behavior repairs.

## Task 2: Preserve truthful worker and container terminal outcomes

Checkpoint completed at `3b926837372f2a878169671911e613968455f553`.
Independent specification and quality review approved the lifecycle repairs
after one fix round. Evidence includes all eight native host integration tests,
19 runner tests, 27 Python process tests, strict Clippy and formatting.
Actual Docker host-loss and combined-foundation qualification remain Task 5
requirements, not claims of this checkpoint.

**Files:** `crates/products/chio-cli/src/cli/process_host/runner/{mod,child,
container,journal,plan}.rs`, adjacent focused modules when separating actual
completion from diagnostics, `crates/products/chio-cli/tests/process_host/`,
`sdks/python/chio-process/src/chio_process/container.py`, its tests, and the
existing process runner/container contract documents.

**Interfaces:** The existing `Outcome`, `Completion`, `Journal::finish`, container
ownership records and credential revocation remain the authority. Separate an
observed worker exit from log retention and pending cleanup without declaring
the run exportable while an owned container may remain alive.

- [x] Add failing table-driven native/Python tests for `created` with exit code
  zero, a failed start attachment, live/unknown container states, successful
  exit with failed log retention, and successful exit with failed cleanup.
  Literal expectations: never-started is not completed; durable observed success
  survives diagnostic failure; unresolved ownership blocks replacement/export.
- [x] Add an interruption regression where an already-observed completion and
  termination are simultaneously ready; consume known completions before
  recording interruption for unfinished workers.
- [x] Validate immutable plan commands and working directories before charging
  attempts. Preserve the configured attempt deadline during bootstrap writes;
  do not spend a separate fixed five-second startup budget.
- [x] Keep derived status publication observational after journal commit. Retain
  actual completion through publication failure, while preserving fatal initial
  readiness checks and explicit diagnostics.
- [x] Preflight required pidfd support and preserve definite pre-execution versus
  ambiguous launch failures. Pin resident-memory sampling to the owned child
  identity, not a reusable numeric PID. Preserve final resource accounting.
- [x] Distinguish definitive create rejection plus authoritative absence from
  uncertain creation. Cover Python bounded collection and exact-owner cleanup.
  Preserve worker restart semantics with stable logical operation identities;
  restart is not permission to redispatch an unknown tool effect.
- [x] Run each new regression red against inherited code, implement its smallest
  state transition, rerun green, then run the native process-host and Python
  container suites. Use real journal persistence and filesystem faults. Engine
  doubles may model unavailable Docker responses but must not replace the code
  deciding completion or ownership.
- [x] Commit and independently review. Real Docker host-loss qualification stays
  explicitly required for the container profile, separate from unit tests.

## Task 3: Close process lineage and retained-response integrity gaps

Checkpoint completed at `ac2ca99973f24048b57b87e78cae4b61fa1d1d65`.
Independent specification and quality review approved the integrity repairs
with no new task findings. Covering gates passed 1,722 Rust and 334 Python tests,
the live no-bypass checker, strict affected Clippy and formatting. One inherited
kernel-core documentation example remains ignored. These counts exclude repeated
and nested fixture executions, and do not represent whole-workspace qualification.
The reproduced ordinary-clock threshold recovery failure remains assigned to
Task 4's durable-store group; 11 inherited mini-SWE import-order lint findings
remain assigned to its SDK group. Neither is treated as a passing gate here.

**Files:** `crates/kernel/chio-process/src/lib.rs`, focused process tests,
`crates/kernel/chio-kernel-core/tests/signed_lineage.rs`,
`xtask/src/adapter_no_bypass.rs`,
`crates/products/chio-cli/src/cli/process_response_verify.rs`, its tests and the
Python process SDK's verification documentation.

**Interfaces:** Existing kernel signed-denial APIs and canonical capability
lineage verification; `ProcessRuntime` stable request identities; the CLI's
independent retained-response verification. Do not create a second receipt or
dispatch authority.

- [x] Reproduce missing signed denials for invalid/revoked/expired process
  lineage. Route attempts to the owning kernel denial boundary while retaining
  exact ancestor snapshots and preventing dispatch or output release.
- [x] Add negative lineage cases with missing Delegate permission, invalid link
  times, repeated identities and mismatched signed root. Assert the specific
  owning refusal, not a generic error from an unrelated malformed fixture.
- [x] Update the no-bypass contract to the actual shared evidence verifier and
  execute its behavioral/source-graph checker.
- [x] Classify read-only redispatch eligibility inside the owning kernel using
  actual matching grants. Exclude monetary, quota, aggregate, cumulative,
  finding-recovery/delivery and native/runtime/approval/DPoP authority as well as
  all existing id-bound artifacts. Matching errors deny retry. Test the attempt
  cap and retained original charge/hold identity under uncertainty.
- [x] Replace incomplete signed uncertainty metadata with a truthful registered
  typed projection and update its consumers together, preserving retained
  evidence. Do not manufacture completion merely to satisfy the schema.
- [x] Require every originally selected runtime, approval and DPoP custody
  participant before producing a caller snapshot; test missing selections and
  genuinely unselected legacy absence without refunding unknown effects.
- [x] Add retained-response attempt-two/three positive bindings and wrong request
  identity/attempt negatives. Share the existing bounded-attempt contract through
  a public narrowly documented constant or identity helper instead of duplicating
  a literal upper limit in the CLI.
- [x] Clarify Python normalization versus direct retained JSON verification.
  Preserve original signed receipts and never retry on verification failure.
- [x] Run red/green regression cycles, focused suites and strict Clippy; commit
  and review the complete integrity repair.

## Task 4: Reconcile the remaining inherited review findings

The durable-store and administration subgroup is complete at
`1f2c8c3e9d8c074d4e50181201ce4e788bc47d0d`, with all 29 assigned threads
reconciled against current source. Repairs preserve cancelled-process inspection,
legacy mailbox ownership, authority-time refusal, truthful no-op accounting and
mutation-safe administration. Ordinary-clock threshold recovery now runs in the
normal test inventory. Independent review identified and closed two relocation
ordering defects: valid committed imports remain recoverable with live WAL, and
orphan sidecars refuse before authority retirement. Real WAL, filesystem and
callback-refusal tests cover both recovery and unchanged-state boundaries.

Affected kernel, process, SQLite, control-plane and CLI gates passed, with strict
Clippy and formatting. This is a reviewed local subgroup checkpoint, not combined
workspace or hosted qualification. The inherited 2,005-line admission
coordinator hygiene failure is addressed by the CI/classifier subgroup's
payment-journal extraction, without changing the limit.

The SDK response/resource subgroup is complete at
`627dc589b28ab60ef391ad866009cefa31c44f5d`, with all 11 assigned threads
reconciled and independent review reporting no Critical or Important findings.
Repairs bound inline stream consumption, preserve complete blob replay and
pending operation identity, distinguish approval/denial/invalid responses, and
bind container cleanup to the created identity. Supported adapters, storage
schemas and explicit environment configuration remain available.

Covering tests passed 522 unique automated cases. Both AI SDK 6/7 installed
profiles passed the selected tool/recovery, journal and pressure scenarios.
The broader interrupted invocation is not full qualification: complete swarm
and supervision runs remain required in Task 5 after artifact/example repairs.
Inherited LangGraph package typing/style failures and its compatibility warning
also remain Task 5 work.

The installed-artifact and example subgroup is complete at
`bb338d9e5160cdad5984bf334b65bf2fc15ed34d`, with all 26 assigned threads
reconciled. Repairs preserve exact package selection, isolated Python startup,
bounded adaptive handoffs/publication, canonical ownership checks, signed
publication integrity and truthful scheduler/evidence assertions. A separately
committed caller-share clock repair sequences the snapshot observation with
existing admission mutations, without weakening expiry or retained-unknown
accounting. Concurrent physical-clock legacy and adaptive profiles passed.

Independent review closed an additional socket-path preflight defect with
exact byte-boundary refusal/fallback tests and real maximum-length socket binds.
The affected 62-case review suite passed after that correction. Earlier native
and installed qualification retains its recorded source identity at
`0def619be29c4da48a94d21f66b033c12a10b0ca`; the final two-file qualifier fix did
not change the native binary or rerun those full profiles. Task 5 still owns
combined final-source qualification and the minor standalone authorization
check's unnecessary ambient mini-SWE initialization.

The CI/classifier subgroup is implemented and locally checked through
`a6d3690a42`, with all ten assigned thread dispositions recorded. Nullable
classification rules and malformed JSON Pointers reject at load; explicit
checkout anchors support out-of-tree conformance binaries. Required CI now
joins the nonce/FIPS inventory and refuses missing committed Linux evidence.
Dependency-parser and nested-manifest regressions preserve the custody boundary
and select all 30 fuzz targets. Payment journal methods moved unchanged into
their own module, resolving the coordinator size failure.

The subgroup's covering logs contain 245 distinct passing Rust tests. Focused
Python fixtures, strict owning-package and CLI Clippy, workflow lint, Rust
formatting, dependency-tree, no-bypass and hygiene checks passed. Direct root
review replaced further agent delegation at the user's request. The complete
security source contract still fails on its execution-image Cargo.lock digest
ratchet, which already differed from the subgroup base. Task 5 must reconcile
final candidate image inputs and the separate trusted-execution authorization;
neither assertion nor controller pin was changed in this subgroup.

The final 109-thread disposition record remains pending. Focused preparation
confirmed timeout default/override preservation, rich native caller attachments,
signed caller schemas and selected-native enforcement before Optional fallback.
No merge or hosted qualification is claimed by these subgroup checkpoints.

**Files:** The committed review-disposition record beside this plan, and only the
source/tests owned by verified findings in the process/security integration.

**Interfaces:** Each finding maps to its original PR/thread, exact current
source, violated invariant, regression and disposition. Review text alone is
not sufficient to mark a repair complete or discard valuable functionality.

- [ ] Enumerate the inherited process PRs by actual ancestry and load their
  review threads. Include #1117's still-open findings in the combined audit.
- [ ] For each finding, record fixed-with-evidence, reproduced-and-repaired,
  technically-inapplicable-with-reason, or unresolved. Prior fixes remain fixes;
  do not redo them merely because the old thread is unresolved.
- [ ] Repair reproduced security, recovery, correctness and validation defects
  through focused TDD tasks, grouping only closely related changes. Preserve
  supported adapters, process ABI handling, mailbox semantics and resource bounds.
- [ ] Add the reconciliation review's remaining expiry oracles through joint
  budget authorization/capture, post-return claims, approved-caller replay and
  reserved-terminal active claims. Refusal must preserve participant, claim,
  commit-chain and anchor state, without charging a replay.
- [ ] Reply in the original thread with exact committed evidence after review.
  No cosmetic cleanup or unverified claim may conceal an unresolved invariant.

## Task 5: Qualify the combined foundation

**Files:** Existing process/security CI inventories, evidence scripts, proof
source inventories and qualification documentation. Dependencies change only
when a reproduced build/audit failure requires a scoped reviewed correction.

**Interfaces:** One exact candidate and its effective feature graph. Source
qualification and actual native enforcement remain separately named evidence.

- [ ] Run the complete workspace gate, process worker/mailbox features, native
  process-host recovery, independent response verification, Python/Node SDK
  tests, signed lineage and M1-M4 exact security inventories. Keep logs tied to
  exact source and compiler identity, including failures and retries.

  ```sh
  cargo build --locked --workspace
  cargo test --locked --workspace
  cargo clippy --locked --workspace -- -D warnings
  cargo fmt --all -- --check
  cargo test --locked -p chio-process --features worker-server,mailboxes
  cargo test --locked -p chio-cli --test process_host
  cargo test --locked -p chio-cli --test process_response_verify
  ```

- [ ] Check dependency advisories and required audits without adding unreviewed
  exemptions. Reconcile changed manifest fuzz selection and generated coverage.
- [ ] Run `graphify update .` after the final code changes. Obtain a broad
  independent review of reconciliation, repairs and remaining dispositions.
- [ ] Acquire actual supported native/container qualification only through an
  authorized route. Do not modify trusted-source pins or privilege boundaries
  under the guise of repairing ordinary CI.

## Task 6: Integrate qualified dependency-complete changes

**Files:** Git/PR metadata and an exact-head qualification record.

**Interfaces:** Current #1117 security foundation and the reconciled process
candidate; no unrelated product or historical omnibus PR is pulled in.

- [ ] Push the reviewed candidate and create or update a clearly based
  integration PR preserving both ancestries and linking superseded review slices.
- [ ] Reconcile local, remote and PR head SHA, required terminal CI attempts,
  unresolved threads and actual review decisions. Re-run after any source/base
  change. Green stacked checks against an old parent do not qualify the new base.
- [ ] Merge only dependency-complete qualified changes using protected normal
  merge controls. If required checks or new operator authority block merge,
  report the exact boundary without bypassing it or declaring integration done.
- [ ] Confirm resulting main ancestry and current CI. Close historical slices
  only after proving their functionality and fixes are present in merged source.

## Task 7: Execute M5 on the integrated process foundation

**Files:** `examples/reference-swarm`, existing process host/runtime wiring,
runtime authority stores, independent evidence verification and the authorized
M5 qualification operation. This task retains every requirement of M5 in
`launch-execution-plan.md`; it is not replaced by the process demos.

- [ ] Bind actual persistent process capabilities and authenticated workers into
  the signed task graph. Install verifier-owned live swarm/runtime authority and
  require swarm admission on the selected edges.
- [ ] Use the real durable aggregate budget and single-use continuation custody.
  The process journal's logical-call ceiling remains a separate upper bound.
- [ ] Launch real Enforced tools with signed manifests and trusted evidence;
  preserve the existing Disabled integration smoke under its honest name.
- [ ] Execute success, scope widening, forbidden filesystem/network, cross-agent
  leakage, shared-budget contention, continuation replay, crash/restart and
  revocation with both caller-output and external-effect assertions.
- [ ] Independently verify one exact-run artifact joining capabilities, workers,
  graph, receipts, accounting, confinement and terminal outcomes. Only that
  complete result closes M5. Any unavailable required authorization or platform
  remains explicit and does not relax the milestone.
