# Shared Desktop Operator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Ship one operator experience over the existing work, recovery and security owners, with sealed single-owner work as its first execution product.

**Architecture:** A new outside-TCB controller projects owner contracts to the existing workbench first. Omarchy and macOS add thin clients and qualified isolation adapters. The owner programs retain authority, durable state, process custody, evidence and runtime qualification.

**Tech Stack:** Rust owner clients and local authenticated IPC; existing workbench browser UI; platform QML and SwiftUI shells; existing restricted launchers and container execution.

`boundary_class: advisory_only` for the common controller; `planning_status: ready_after_adr` under [ADR-0038](../../adr/ADR-0038-desktop-operator-program.md). Native pre-effect gates retain their owners' `prevent` classification; observations remain `detect_only`.

## Execution contract

This is a dependency-gated integration plan. It does not invent code against
unlanded APIs. Work packets 1-3 reconcile and qualify predecessor contracts;
packet 3 may create generated candidate bindings and conformance probes; packets 4-6 create product runtime code after that candidate is approved. At each code packet, expand the
now-pinned owner API into a test-first patch plan with actual types and complete
code before implementing it. A missing type or query stops that packet and
returns the change to its named owner. It does not license a desktop substitute.

The [program map](../../architecture/PROGRAM-MAP.md) contains exact source pins
and existing paths. [OPERATOR](../../../spec/OPERATOR.md) and
[QUALIFICATION](../specs/2026-10-07-desktop-integration/QUALIFICATION.md) define
the required results. Platform plans cover their remaining lifecycle work.

## File ownership

| Location | Responsibility and availability |
| --- | --- |
| `spec/OPERATOR.md` | Proposed common projection; freeze only after owner schemas land |
| `docs/architecture/PROGRAM-MAP.md` | Source owner register and dependency acceptance |
| `crates/products/chio-operator/` | Proposed new crate for bounded view composition and owner dispatch; no native authority |
| `crates/products/chio-workbench/` | Existing first client on the pinned workbench branch; review and worktree UX |
| `tests/integration/operator/` | Proposed installed-owner, cross-client acceptance harness; no fake runtime success |
| `crates/security/chio-secure-ipc/` | Existing native peer authentication; Darwin extension belongs here |
| `crates/kernel/chio-process/`, `crates/products/chio-cli/PROCESS_HOST.md` | Existing process identity/custody/control; live control delta belongs here |
| `sdks/python/chio-mini-swe/` | Existing sealed runner, verified export and evaluator integration |
| Platform annexes and `integrations/`, `packaging/` targets named there | Native presentation, packaging and platform acceptance |

## Packet 1: Reconcile predecessor source and handoffs

`boundary_class: advisory_only`; `planning_status: ready_after_adr`.

**Files:** Update `docs/architecture/PROGRAM-MAP.md`; add implementation-time
`docs/superpowers/evidence/desktop-operator/predecessors.md`. Owner changes go to
the exact paths in the map, not a desktop fork.

- [ ] Read every pinned owner document using `git show <full-pin>:<path>` from the register. Record the landed successor commit or explicit unmet gate for each row.
- [ ] Reconcile W1.0 against the actually landed recovery/process ABI. Record the real WorkClient/WorkTransport methods, work queries, preparation lookup and six observations before compiling a client.
- [ ] Open the foundation landing ledger and workbench inherited findings. Bind acceptance to the selected source/profile; do not copy historical M0-M4 counts into a release verdict.
- [ ] Record owner handoffs for S9's narrowly sequenced M20 delta, S7 new kinds, S1 controller classification and the ADR-0023 thin-adapter/grant split. These are amendments required in those programs.
- [ ] Record the approval utility's installed archive pin and Q05's deny/ID-mismatch cases with the host owner. Record missing production approval-path integration and S28 attribution separately.
- [ ] Commit the reconciled dependency record with `docs(desktop): pin operator predecessors`. A missing gate remains unavailable and blocks only its dependent behavior.

**Acceptance:** Every desktop concept has exactly one owner and an inspectable
source. No uncommitted worktree is a predecessor. No open upstream branch alone
counts as a design defect; missing required native acceptance still blocks use.

## Packet 2: Qualify the event, recovery and operator lanes

`boundary_class: prevent` for owner actions and `detect_only` for event views;
`planning_status: ready_after_adr`.

**Files:** Owner S3/S4/S5/S8/S9 design paths in PROGRAM-MAP; their owning crates;
`docs/superpowers/evidence/desktop-operator/predecessors.md`.

- [ ] Land and qualify S5 Part A, S3 phase 1 and the owner-reviewed M20 disposition delta. Verify terminal receipts and retained uncertainty with post-effect failures (Q02-Q04).
- [ ] Qualify S8 phase 1 kernel-scope stop and S30 reach. Keep tenant/recovery stop unavailable until phases 4/5. Record route authorization and restart evidence (Q08).
- [ ] Qualify S4 phases 1/2 and process-host live cancel/revoke. Reuse `cargo test --locked -p chio-cli --test process_host` for the existing process-host suite, then add native Q07/Q19 regressions in that owner. Existing stopped-host tests alone do not prove live control.
- [ ] Implement S5 Part B as the explicit second wire consumer. Qualify stable subscription identity, gap/restore semantics, authorization and non-persisting re-reads. Reproduce Q09/Q21 without spending the work's settlement reserve.
- [ ] Qualify W1 preparation/command/work lookup with lost replies and missing handles; qualify recovery repairs at its current tree. Absence from one read is not proof no original effect occurred.
- [ ] Qualify S28 roster plus the production endorsement path and installed native approval fix. Q05/Q06 must prove no retained approved artifact for deny or a mismatched approval ID.
- [ ] Commit owner changes in their own programs, then update only the desktop dependency references. Do not use a green desktop mock to close any owner gate.

## Packet 3: Prepare one wire candidate after its owners

`boundary_class: advisory_only`; `planning_status: ready_after_adr`.

**Files:** `spec/OPERATOR.md`; owner schemas; proposed
`tests/integration/operator/` and qualification manifest.

- [ ] Resolve work enumeration, scope/health views and authenticated recovery reads through their owners. W1's existing query inventory does not imply ListWork exists.
- [ ] Import the landed work/recovery/event/stop types. Write one generated wire binding for `chio.operator.v1`; retire platform names with no compatibility fallback because neither was released.
- [ ] Encode full request/response identity, native session/audience and intent correlation, including errors, retries and pagination. Run Q04 substitutions individually against valid controls.
- [ ] Cover Q15/Q16: unique dimension budgets with exact units/bounds, missing values distinguished from unlimited, nonempty evaluated profiles and fresh evidence. Require the installed owner to enforce each claimed limit.
- [ ] Freeze bounded frame/list/event limits and their refusal behavior from owner constraints and measurements. Unknown versions and unsupported owner capabilities fail explicitly.
- [ ] Record provisional schema/binding approval with source hashes and owner-conformance probe results. Commit `feat(operator): add candidate owner projection`. This permits packet 4 development, not a frozen client ABI or release. Final wire freeze waits for the implemented-client acceptance at the end of packet 4.

**Acceptance:** No copied WorkPhase, retry enum, event store, capability issuer,
receipt signer or approval state machine. Schema success alone cannot satisfy
the installed-owner correlation tests.

## Packet 4: Implement the common controller and workbench client

`boundary_class: advisory_only` for the controller; `planning_status: ready_after_adr`.

**Files:** Create `crates/products/chio-operator/{Cargo.toml,src/lib.rs,src/main.rs}`
and `tests/integration/operator/` after packet 3; modify workspace `Cargo.toml`.
Adapt existing `crates/products/chio-workbench/src/{model.rs,engine.rs,web.rs}`,
`web/{app.js,index.html,style.css}` and its `tests/{workbench.rs,git_tasks.rs,browser-smoke.mjs}`.

- [ ] Write red tests for independent work observations, stale/error replies, absent owners and authority-bearing material in UI state. An unavailable owner must produce an explicit unavailable feature, not fixture data.
- [ ] Implement authenticated owner connections and bounded in-memory projection only. Keep gateway/process host in separate processes. Bind browser sessions to local authenticated context; prohibit authority tokens in URLs and logs.
- [ ] Adapt the workbench to this projection while preserving worktrees, patch SHA-256 and reviewable differences. Close its inherited findings before counting the workbench as accepted.
- [ ] Run `cargo test --locked -p chio-operator` once the proposed crate exists; run the existing `cargo test --locked -p chio-workbench --test workbench` and `cargo test --locked -p chio-workbench --test git_tasks` against the reconciled workbench branch. Expected: all targeted owner/client cases pass, no skips masquerading as acceptance.
- [ ] Execute the browser suite using the workbench's installed dependencies and documented fixture server. Exercise keyboard, screen reader, untrusted artifact content, revoked session and reconnect. Retain screenshots plus the native owner transcripts (Q17).
- [ ] Measure idle/cold/warm resource use, event pressure and restart recovery. Freeze numeric release bounds and verify overload refuses new work without weakening a gate.
- [ ] Run the protocol-freeze matrix against the implemented workbench client and the independent conformance client from packet 3. Freeze `chio.operator.v1` only after these cross-client/native results pass; schema changes during development return to packet 3 conformance.
- [ ] Commit `feat(operator): add workbench owner client` after code, security-boundary, final wire-freeze and native acceptance review.

## Packet 5: Deliver sealed work using the existing runner

`boundary_class: prevent` at kernel-owned tool routes;
`planning_status: ready_after_adr`.

**Files:** Existing mini-swe `repository_container.py`, `repository_proof.py`,
`repository_review.py`, model/gateway owner paths; W1 owner; selected host
integration; workbench client; S7 owner evidence registration.

- [ ] Bind the fixed recipe, project/base, artifact policy, evaluator, limits and acceptance contract to W1. Preserve original identity through every recovery action.
- [ ] Reuse network-less container execution and restricted host tools. If native Seatbelt/bubblewrap is selected, require that exact launch/egress/descendant tuple and new S7 kind first; never run Node in the tool-server cage.
- [ ] Place any external acceptance oracle in the runner/work owner. Bind its evidence to the original contract; keep artifact creation, acceptance, settlement and external delivery separate.
- [ ] Run Q11-Q15 and Q18-Q20 against installed builds, including malformed exports and retained child processes. The controller does not implement a second artifact trust checker or supervisor.
- [ ] Complete one unpaid work commitment end to end: approve exact scope, execute, stop/recover, inspect the patch and original evaluator-derived acceptance, approve/reject patch application, then separately request scoped publication. Human patch review never sets W1 acceptance. Prove a denial produces no publication effect.
- [ ] Qualify Pi's exact current tuple first. Keep the six-host matrix open until every doc 19 host independently passes I01-I08; add hosts without changing the common task model.
- [ ] Commit owner extensions and the workbench workflow in reviewable slices; promote no release based only on this successful development run.

## Packet 6: Add platform clients and release

`boundary_class: advisory_only` for native UI; `planning_status: ready_after_adr`.

**Files:** [Omarchy plan](2026-10-07-omarchy-integration/IMPLEMENTATION.md) and the
dependent macOS plan at `docs/superpowers/plans/2026-10-07-macos-integration/IMPLEMENTATION.md`.

- [ ] Execute the platform plan after common-client acceptance. Reuse the same controller, work identifiers, recovery and projection tests.
- [ ] Execute the complete installed qualification manifest with explicit reasons for owner-approved exclusions. Missing evidence or tuple substitutions fail qualification.
- [ ] Publish signed qualification inputs to the candidate channel, install on clean hosts, and run upgrade/crash/rollback/uninstall exercises before promotion.
- [ ] Record public artifact availability separately from native acceptance. Verify that public checkout instructions use public revisions, not this internal source register.
- [ ] Promote the exact qualified tuple and keep the stop/rollback runbook reachable when the UI is unavailable. Record hosted checks, release publication and bot review separately.

Boundary interactive and managed endpoint remain deferred. Omarchy compositor
tools, configuration repair and desktop-owned delegation have no delivery
packet. Adding them back requires a new scope decision, not a late task inserted
into this plan.
