# Shared Desktop Operator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Ship one operator experience over the existing work, recovery and security owners, with sealed single-owner work as its first execution product.

**Architecture:** A new outside-TCB controller projects owner contracts to the existing workbench first. The existing Chio CLI adds a terminal consumer; Omarchy and macOS add thin clients and qualified isolation adapters. The owner programs retain authority, durable state, process custody, evidence and runtime qualification.

**Tech Stack:** Rust owner clients and local authenticated IPC; existing workbench browser UI; platform QML and SwiftUI shells; existing restricted launchers and container execution.

`boundary_class: advisory_only` for the common controller; `planning_status: ready_after_adr` under [ADR-0038](../../adr/ADR-0038-desktop-operator-program.md). Native pre-effect gates retain their owners' `prevent` classification; observations remain `detect_only`.

## Execution contract

This is a dependency-gated integration plan. It does not invent code against
unlanded APIs. Work packets 1-3 reconcile and qualify the selected profile's
predecessor contracts. Packet 2's Observe lane independently permits a read-only
packet 3 candidate and packet 4 client; its operator lane gates only the selected
work/recovery/approval/stop capabilities. Packet 3 may create generated candidate
bindings and conformance probes; packets 4-6 create product runtime code after
the selected candidate is approved. At each code packet, expand the
now-pinned owner API into a test-first patch plan with actual types and complete
code before implementing it. A missing type or query stops that packet and
returns the change to its named owner. It does not license a desktop substitute.

The [program map](../../architecture/PROGRAM-MAP.md) contains exact source pins
and existing paths. [OPERATOR](../specs/2026-10-07-desktop-integration/OPERATOR.md) and
[QUALIFICATION](../specs/2026-10-07-desktop-integration/QUALIFICATION.md) define
the required results. Platform plans cover their remaining lifecycle work.

## File ownership

| Location | Responsibility and availability |
| --- | --- |
| `docs/superpowers/specs/2026-10-07-desktop-integration/OPERATOR.md` | Current proposed common projection; owner schemas and profile-specific acceptance govern promotion |
| `spec/OPERATOR.md` and `spec/README.md` | Future normative projection and index entry, created only at packet 4's implemented-client wire freeze for the exposed profile |
| `docs/architecture/PROGRAM-MAP.md` | Source owner register and dependency acceptance |
| `crates/products/chio-operator/` | Proposed new crate for bounded view composition and owner dispatch; no native authority |
| `crates/products/chio-workbench/` | Existing first client on the pinned workbench branch; review and worktree UX |
| `crates/products/chio-cli/` | Existing `chio` binary; packet 4a adds an operator consumer through current CLI parsing/dispatch owners, without a new launcher or authority path |
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
- [ ] Record the existing trust-control GET owners and host-plugin/bridge provenance before compiling the read-only client. Reconcile W1.0 against the actually landed recovery/process ABI before adding W1 capabilities; record the real WorkClient/WorkTransport methods, work queries, preparation lookup and six observations. Missing W1 does not block basic receipt/hook observation.
- [ ] Open the foundation landing ledger and workbench inherited findings. Bind acceptance to the selected source/profile; do not copy historical M0-M4 counts into a release verdict.
- [ ] Record owner handoffs for S9's narrowly sequenced M20 delta, S7 new kinds, S1 controller classification and the ADR-0023 thin-adapter/grant split. These are amendments required in those programs.
- [ ] Record the approval utility's installed archive pin and Q05's deny/ID-mismatch cases with the host owner. Record missing production approval-path integration and S28 attribution separately.
- [ ] Commit the reconciled dependency record with `docs(desktop): pin operator predecessors`. A missing gate remains unavailable and blocks only its dependent behavior.

**Acceptance:** Every desktop concept has exactly one owner and an inspectable
source. No uncommitted worktree is a predecessor. No open upstream branch alone
counts as a design defect; missing required native acceptance still blocks use.

## Packet 2: Qualify Observe and selected operator lanes independently

`boundary_class: prevent` for owner actions and `detect_only` for event views;
`planning_status: ready_after_adr`.

**Files:** Owner S3/S4/S5/S8/S9 design paths in PROGRAM-MAP; trust-control read
handlers and host observation adapters; their owning crates;
`docs/superpowers/evidence/desktop-operator/predecessors.md`.

### Observe lane

- [ ] Land and qualify S5 Part A, then Part B with desktop as the explicit second wire consumer. Qualify stable subscription identity, gap/restore semantics, audience authorization and bounded non-persisting re-reads. Reproduce Q09/Q21 without spending the work's settlement reserve. Recovery projection waits for its landed event/read owner; work projection waits for the W1 query, matching S5's per-source gates.
- [ ] Bind the existing trust-control receipt query/analytics/tool/child, lineage, budget-usage and revocation GETs through bounded authenticated read adapters. Preserve native read-principal rules and exclude mutation methods even where paths are shared. Qualify request/filter/pagination correlation (Q04) and explicit feature availability (Q16).
- [ ] Qualify the host owner's session/capability/receipt joins and hook source attribution (Q11). Host-reported success remains unverified and `detect_only`; trust-control receipt presence is not proof of a live or complete hook session. Expose no session inventory until its bounded authenticated host adapter exists.
- [ ] Qualify the selected native IPC and non-persisting read adapters, including wrong-session/stale-peer refusal and no quota-draining inspect polling (Q09-Q10/Q21). Missing recovery adapters disable recovery views, not unrelated receipt/hook reads.
- [ ] Record Observe predecessor acceptance. This independently permits the read-only packet 3 candidate and packet 4 controller/workbench work. Its complete client acceptance is Q04, Q09-Q11, Q16-Q17 and Q21, plus Q15 for selected budget projections. Q02 applies to each exposed effecting owner, including selected support-export/lifecycle actions without W1/M20; Q01/Q03 add only the relevant W1/recovery view obligations. Pure reads acquire no mutation-race dependency.

### Selected operator/work/recovery lane

- [ ] For selected effect paths, land and qualify S3 phase 1 and the owner-reviewed M20 disposition delta. Verify terminal receipts and retained uncertainty with post-effect failures (Q02-Q04). These are not prerequisites for basic receipt/hook observation.
- [ ] Qualify S8 phase 1 kernel-scope stop and S30 reach. Keep tenant/recovery stop unavailable until phases 4/5. Record route authorization and restart evidence (Q08).
- [ ] Qualify S4 phases 1/2 and process-host live cancel/revoke. Reuse `cargo test --locked -p chio-cli --test process_host` for the existing process-host suite, then add native Q07/Q19 regressions in that owner. Existing stopped-host tests alone do not prove live control.
- [ ] Qualify W1 preparation/command/work lookup with lost replies and missing handles before exposing those capabilities. Qualify recovery repairs at their current source, with complete dispositions for historical, merged/predecessor and later findings. Calling the old counts historical does not resolve them. Absence from one read is not proof no original effect occurred.
- [ ] Qualify S28 roster plus the production endorsement path and installed native approval fix. Q05/Q06 must prove no retained approved artifact for deny or a mismatched approval ID.
- [ ] Commit owner changes in their own programs, then update only the desktop dependency references. Do not use a green desktop mock to close any owner gate.

**Acceptance:** Each capability records its own predecessor evidence. Observe may
advance while S4/S8/S28/M20/W1 or mutation recovery gates remain unmet; those
capabilities stay explicitly unavailable. Passing one lane does not close another.

## Packet 3: Prepare the selected wire candidate after its owners

`boundary_class: advisory_only`; `planning_status: ready_after_adr`.

**Files:** `docs/superpowers/specs/2026-10-07-desktop-integration/OPERATOR.md`;
owner schemas; proposed
`tests/integration/operator/` and qualification manifest.

- [ ] After packet 2's Observe lane, resolve selected read, scope/health and host provenance views through their owners. Add authenticated recovery reads and work enumeration only after their independent gates pass. W1's existing query inventory does not imply ListWork exists.
- [ ] Import landed read/event types for the read-only candidate, then work/recovery/stop types only for separately eligible capabilities. Write one generated wire binding for `chio.operator.v1`, with an explicit supported-capability set and unavailable results for absent owners; retire platform names with no compatibility fallback because neither was released.
- [ ] Encode full request/response identity, native session/audience and intent correlation, including errors, retries and pagination. Run Q04 substitutions individually against valid controls.
- [ ] Cover Q16's nonempty evaluated profiles and fresh evidence. For any exposed typed budget/limit capability, also cover Q15: unique dimensions with exact units/bounds, missing values distinguished from unlimited and independent native enforcement of each claimed limit. A read-only usage row makes no new enforcement claim.
- [ ] Freeze bounded frame/list/event limits and their refusal behavior from owner constraints and measurements. Unknown versions and unsupported owner capabilities fail explicitly.
- [ ] Record provisional schema/binding approval for the exact supported capabilities with source hashes and owner-conformance probe results. Commit `feat(operator): add candidate owner projection`. This permits packet 4 development, not a frozen client ABI or release. A read-only candidate does not wait for unexposed mutations. Final wire freeze waits for implemented-client acceptance at the end of packet 4.

**Acceptance:** No copied WorkPhase, retry enum, event store, capability issuer,
receipt signer or approval state machine. Schema success alone cannot satisfy
the installed-owner correlation tests.

## Packet 4: Implement the common controller and workbench client

`boundary_class: advisory_only` for the controller; `planning_status: ready_after_adr`.

**Files:** Create `crates/products/chio-operator/{Cargo.toml,src/lib.rs,src/main.rs}`
and `tests/integration/operator/` after the selected packet 3 candidate; modify
workspace `Cargo.toml`. At final wire freeze, promote the accepted projection to
`spec/OPERATOR.md` and add its normative entry to `spec/README.md`.
Adapt existing `crates/products/chio-workbench/src/{model.rs,engine.rs,web.rs}`,
`web/{app.js,index.html,style.css}` and its `tests/{workbench.rs,git_tasks.rs,browser-smoke.mjs}`.

- [ ] Write red tests for the selected observation surface, stale/error replies, absent owners and authority-bearing material in UI state. Add independent work-observation cases only when W1 is exposed. An unavailable owner must produce an explicit unavailable feature, not fixture data; an Observe build cannot dispatch unqualified mutations.
- [ ] Implement authenticated owner connections and bounded in-memory projection only. Keep gateway/process host in separate processes. Bind browser sessions to local authenticated context; prohibit authority tokens in URLs and logs.
- [ ] Adapt the workbench to this projection while preserving worktrees, patch SHA-256 and reviewable differences. Close its inherited findings before counting the workbench as accepted.
- [ ] Run `cargo test --locked -p chio-operator` once the proposed crate exists; run the existing `cargo test --locked -p chio-workbench --test workbench` and `cargo test --locked -p chio-workbench --test git_tasks` against the reconciled workbench branch. Expected: all targeted owner/client cases pass, no skips masquerading as acceptance.
- [ ] Execute the browser suite using the workbench's installed dependencies and documented fixture server. Exercise keyboard, screen reader, untrusted artifact content, revoked session and reconnect. Retain screenshots plus the native owner transcripts (Q17).
- [ ] Measure idle/cold/warm resource use, event pressure and restart recovery. Freeze numeric release bounds and verify overload refuses new work without weakening a gate.
- [ ] Run the profile-specific protocol-freeze matrix against the implemented workbench client and the independent conformance client from packet 3. An Observe-only freeze requires its full selected-surface matrix: Q04, Q09-Q11, Q16-Q17 and Q21, conditional Q15 budget projection, Q02 for any exposed effecting owner, and Q01/Q03 only for relevant W1/recovery views. Each capability carries its own owner evidence without turning absent execution into an observation gate. Freeze `chio.operator.v1` for the exact supported surface only after these cross-client/native results pass, promote it to `spec/OPERATOR.md`, and index it in `spec/README.md`. Unexposed mutation contracts remain proposed; later capability additions return to packet 3 conformance and owning qualification.
- [ ] Commit `feat(operator): add workbench owner client` after code, security-boundary, final wire-freeze and native acceptance review.

## Packet 4a: Deliver the existing CLI as an operator client

`boundary_class: advisory_only` for terminal presentation;
`planning_status: ready_after_adr`; not an implemented command surface.

**Depends on:** packet 4's implemented read-only controller and accepted bindings.
Build Observe first without W1/M20 or platform UI dependencies. Each later action
requires its packet 2 owner gate, packet 3/4 capability conformance and, for
sealed execution, packet 5. CLI implementation does not gate candidate assembly
for those predecessors. Packet 6 release includes the promised CLI acceptance.

**Files:** Extend the existing `crates/products/chio-cli/Cargo.toml`,
`src/main.rs`, `src/cli/types.rs` and `src/cli/dispatch/mod.rs`;
create proposed `src/cli/operator.rs` and `tests/operator_client.rs` in that crate,
and extend `tests/integration/operator/`. `src/bin/chio.rs` already includes
`src/main.rs`; keep the existing `chio` binary. Reconcile these source locations
at packet 1 before editing. Update the CLI README/help only after implementation.
The proposed operator subcommand names and flags are chosen against the landed
owner API; existing `chio run` retains its native framed-agent meaning.

- [ ] Register the CLI product owner and exact module/test entrypoints in the predecessor record. Enumerate the promised CLI capabilities and their owner dependencies: authenticated receipt/session/health observation first; sealed-work preparation/submission and views, original-operation lookup/recovery, exact native approval/stop and artifact review/delivery only when individually qualified. An absent capability reports unavailable rather than being omitted from completion accounting.
- [ ] Reuse the generated common client codec and authenticated native controller transport. The operator subcommands do not build an in-process kernel, bootstrap a second controller, load signing/provider secrets, inherit broad admin credentials or call a bypass owner route. An unavailable controller or mismatched profile cannot fall back to existing broad CLI commands. Keep transport limits, audience/session binding and full request/response correlation identical to the other clients.
- [ ] Design human and machine-readable output from the accepted projection. Preserve six work observations and native uncertainty independently; define and test explicit bounded output/exit behavior for unavailable, refused, unresolved and completed requests without a synthetic all-success state. Escape terminal control sequences and display original security-relevant identifiers without hidden normalization; machine output stays parseable, bounded and credential-free. Secret-bearing inputs use the native owner path and private input channels, never argv, environment, shell history or log output.
- [ ] Implement only exact capability-bound requests. Navigation opens a fixed owner-approved review route without authority in its URL; a CLI confirmation flag, unattended input or successful process exit cannot replace passkey approval or evaluator acceptance. Mutations preserve the native original operation identity across response loss. CLI interruption/disconnection ends local observation and does not silently cancel, resume or resubmit work; explicit stop invokes only its separately qualified native scope. Reconnection reauthenticates and resolves the original operation through its owner.
- [ ] Add owner-backed CLI integration cases for wrong peer/session, missing controller/profile, expired/revoked authority, malformed/oversized replies, all Q04 substitutions, event gaps/reconnect, terminal injection and literal operand handling. Exercise exact and changed-intent duplicate races for each exposed mutation (Q02), interrupted stdout/pipe closure, noninteractive input and lost replies/restart. Independent native dispatch, credential-retention and effect observations prove no bypass or duplicate effect. Pair refusals with useful authenticated Observe and each qualified action.
- [ ] Compare CLI and workbench projections of the same native observations, including disagreeing work axes and retained uncertainty, then submit the same native operation identity from both clients concurrently. Native results and downstream effects must agree; clients cannot create competing identity or recovery models. Run `cargo test --locked -p chio-cli --test operator_client` after the proposed test exists, plus the actual existing CLI parsing/help regressions recorded by its owner and the shared installed-client harness. A test double of CLI output alone cannot qualify native behavior.
- [ ] Package the CLI with the exact accepted controller/protocol tuple on each shipped platform. The platform candidate inventories name its final executable identity; installed tests invoke that binary under standard-user enrollment, including update, stale CLI/controller combinations, logout and lost-reply recovery. O7 and M9/M10 consume the shared CLI evidence for their selected capabilities. A native platform shell or independent packet 3 conformance probe cannot stand in for the product CLI.
- [ ] Record candidate-bound CLI acceptance and update help/README with only commands present in that accepted binary. Commit the existing CLI extension in a separate reviewable slice. Shared-program completion and any release claiming CLI support require this packet's actual source and installed results; an unavailable baseline Observe CLI leaves the promised client undelivered.

**Acceptance:** The installed existing `chio` binary is a useful consumer of the
same accepted operator protocol and native outcomes as the workbench. Its exact
capabilities have their own cross-client and installed evidence; it owns no
parallel authority, workflow ledger or task runner. Later profile additions
repeat the relevant source and installed qualification rather than inheriting
Observe acceptance.

## Packet 5: Deliver sealed work using the existing runner

`boundary_class: prevent` at kernel-owned tool routes;
`planning_status: ready_after_adr`.

**Files:** Existing mini-swe `repository_container.py`, `repository_proof.py`,
`repository_review.py`, model/gateway owner paths; W1 owner; selected host
integration; workbench client; S7 owner evidence registration.

- [ ] Require packet 2's selected work/recovery/operator gates and the execution profile's foundation/S7 acceptance. A prior read-only packet 4 freeze provides no mutation or sealed-work qualification.
- [ ] Bind the fixed recipe, project/base, artifact policy, evaluator, limits and acceptance contract to W1. Preserve original identity through every recovery action.
- [ ] Reuse network-less container execution and restricted host tools. If native Seatbelt/bubblewrap is selected, require that exact launch/egress/descendant tuple and new S7 kind first; never run Node in the tool-server cage.
- [ ] Place any external acceptance oracle in the runner/work owner. Bind its evidence to the original contract; keep artifact creation, acceptance, settlement and external delivery separate.
- [ ] Close evaluator confinement before sealed acceptance. The pinned B workbench (`5bdf08fc3573eba00dd2be7b4fab1c22e48db1f7`, `crates/products/chio-workbench/README.md` security section and `src/tools.rs`) runs project checks with operator OS permissions; that source is not a qualified acceptance sandbox. Route all candidate imports/builds/tests through a separately qualified bounded runner boundary with captured inputs, pinned evaluator dependencies and no ambient host files, secrets, network, unrelated process control or owner signing channels. Keep trusted acceptance validation/commit outside candidate execution. At the actual runner/work/S7/process owners, run a known-good positive control and hostile import/build/test probes for outside file/credential access, direct egress, inherited handles, process signals/descendants, forged result channel, exhaustion and interrupted evaluation. Require independent no-effect/closure evidence and no accepted result on failed/unknown evaluation. Record exact commands, source and boundary tuple; existing recipe confinement alone cannot qualify a separate evaluator. Until this gate passes, sealed acceptance remains unavailable in both platform plans.
- [ ] Run Q11-Q15 and Q18-Q20 against installed builds, including malformed exports and retained child processes. The controller does not implement a second artifact trust checker or supervisor.
- [ ] Complete one unpaid work commitment end to end: approve exact scope, execute, stop/recover, inspect the patch and original evaluator-derived acceptance, approve/reject patch application, then separately request scoped publication. Human patch review never sets W1 acceptance. Prove a denial produces no publication effect.
- [ ] Qualify Pi's exact current tuple first. Keep the six-host matrix open until every doc 19 host independently passes I01-I08; add hosts without changing the common task model.
- [ ] Commit owner extensions and the workbench workflow in reviewable slices; promote no release based only on this successful development run.

## Packet 6: Add platform clients and release

`boundary_class: advisory_only` for native UI; `planning_status: ready_after_adr`.

**Files:** [Omarchy plan](2026-10-07-omarchy-integration/IMPLEMENTATION.md) and the
dependent macOS plan at `docs/superpowers/plans/2026-10-07-macos-integration/IMPLEMENTATION.md`.

- [ ] Execute the platform plan after common-client acceptance. Reuse the same controller, work identifiers, recovery and projection tests.
- [ ] Include packet 4a's existing CLI client in the exact platform package/protocol inventory and repeat its selected-capability cross-client tests against the installed binary. Program completion or claims of CLI support require actual CLI results; the workbench/QML/Swift clients cannot substitute.
- [ ] Execute the complete installed qualification manifest with explicit reasons for owner-approved exclusions. Missing evidence or tuple substitutions fail qualification.
- [ ] Publish signed qualification inputs to the candidate channel, install on clean hosts, and run upgrade/crash/rollback/uninstall exercises before promotion.
- [ ] Record public artifact availability separately from native acceptance. Verify that public checkout instructions use public revisions, not this internal source register.
- [ ] Promote the exact qualified tuple and keep the stop/rollback runbook reachable when the UI is unavailable. Record hosted checks, release publication and bot review separately.

Boundary interactive and managed endpoint remain deferred. Omarchy compositor
tools, configuration repair and desktop-owned delegation have no delivery
packet. Adding them back requires a new scope decision, not a late task inserted
into this plan.
