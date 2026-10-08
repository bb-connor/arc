# Native Host Integration Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task by task. Expand each owner-dependent packet against its landed APIs before coding.

**Goal:** Make Chio's Rust kernel a reusable native systems layer for external
applications and agent harnesses on macOS and Linux/Omarchy, with demonstrable
work coordination, shared resources and independently controlled cooperation.

**Architecture:** Existing L0-L3 owners retain authority, process/resource custody,
evidence and recovery. Thin native adapters connect those owners to the OS.
Public Rust/SDK/native clients consume them directly. The workbench and proposed
`chio.operator.v1` are optional consumers. This plan does not mandate a new daemon,
application scheduler or wire protocol.

**Tech stack:** Existing Rust kernel/process/security/platform crates, selected
language SDKs, authenticated native IPC, launchd/systemd and qualified native or
external containment. QML, SwiftUI and browser surfaces apply only to selected
presentation packages. Concrete owner paths are pinned in
[PROGRAM-MAP](../../architecture/PROGRAM-MAP.md).

`planning_status: ready_after_adr` under [ADR-0038](../../adr/ADR-0038-desktop-operator-program.md).
Native operations retain their actual boundary; projections are `advisory_only`.
No implementation or installed release is qualified by this plan.

## Execution contract and file ownership

Read [HOST-CONTRACT](../specs/2026-10-07-desktop-integration/HOST-CONTRACT.md),
[CAPABILITIES](../specs/2026-10-07-desktop-integration/CAPABILITIES.md),
[CONSUMERS](../specs/2026-10-07-desktop-integration/CONSUMERS.md),
[FIRST-CLASS-INTEGRATIONS](../specs/2026-10-07-desktop-integration/FIRST-CLASS-INTEGRATIONS.md) and
[QUALIFICATION](../specs/2026-10-07-desktop-integration/QUALIFICATION.md).
Packet IDs remain stable so platform references survive this amendment.
Claude Code, Codex, Pi and Hermes are required harness integrations; Herdr is a
required workspace/plugin integration with optional installation. Mini-swe is
only an optional reference/test workload. No existing implementation convenience
sets product priority or substitutes for a named integration.

| Location | Responsibility |
| --- | --- |
| PROGRAM-MAP and proposed `docs/superpowers/evidence/native-host/` | Actual owner source, API, qualification and candidate case manifest |
| Existing `chio-kernel`, `chio-process`, `chio-secure-ipc`, store, broker, trust-control, credential and swarm owners | Native semantics; no platform fork of their authority or state |
| Landed W1-W3/recovery and SDK paths reconciled in packet 1 | Work preparation/submission/query, exact recovery and independent owner transport |
| Existing `crates/products/chio-cli/` | Required terminal diagnostic/admin consumer, packet 4a |
| Proposed `tests/integration/native_host/` | Independent installed owner/consumer acceptance; not a fake runtime |
| Platform `integrations/` and `packaging/` paths selected in annexes | Native ports, installation, update/removal and optional UI |
| `OPERATOR.md`; proposed `chio-operator` and `tests/integration/operator/` | Optional projection only, with its own freeze and complete selected-surface gates |
| Existing workbench and mini-SWE owner paths | Optional application and coding workload, with inherited owner findings and evaluator/export gates |

Code tasks begin only after the selected owner API exists or its owner approves
and implements the missing delta. Record actual types, source/test paths, test
commands and expected refusals at that point. Do not invent runnable commands
for proposed crates or reuse a same-named historical ABI blindly. Independent
capability slices can proceed in parallel once their own gates pass. An absence
is recorded as unavailable and never as a skipped passing test.

## Packet 1: Reconcile source, capability and deployment profiles

**Files:** PROGRAM-MAP, selected owner specs and the proposed predecessor record.

- [ ] Read the exact pinned sources and public documentation observations. Replace each historical owner pin with its intended landed successor or an explicit unmet dependency. Preserve candidate, test-only, planned, installed-qualified and public-release status separately.
- [ ] Create a decision record for every CAPABILITIES row: consumer problem, existing primitive, authoritative owner, OS binding, source status, chosen profile, required gate and reason for each excluded capability. Cover passports, delegation, swarm graphs, resources, work, federation and recovery explicitly.
- [ ] Select embedded, user-session or independently enrolled service-principal deployment. Bind principal, audience, code/peer identity, credentials, storage, boot/incarnation, expiry, lock/logout and removal semantics. A background launcher cannot convert a session capability to a service grant.
- [ ] Reconcile process ABI conflicts and real source symbols. W1.0 must bind actual Prepare/Submit/Query and release/recovery APIs before exposure; proposed WorkClient/WorkTransport names are not implementation evidence. Basic authenticated receipt/hook observation does not wait for W1.
- [ ] Inventory existing trust-control GETs and bounded host provenance adapters. Native read-principal rules apply; paths shared with mutation handlers remain method-restricted. No authoritative session/work inventory is inferred from receipt queries.
- [ ] Record exact owner deltas for Darwin IPC, multi-client enrollment, live process control, S3 post-effect handling, focused S9 M20 dispositions, S7 new evidence kinds, S28/production approval and S5 per-source streams. Record installed approval utility repair separately from wrapper refusal.
- [ ] Reconcile the NVIDIA strategy's proposed isolation/custody freeze with ADR-0038 and the user-approved kernel direction. Keep replaceable containment and measured seam limits; do not adopt its narrower product category, broker freeze or commercial decisions implicitly.
- [ ] Freeze a selected-profile case inventory joining every normative HOST-CONTRACT/CONSUMERS/CAPABILITIES obligation, applicable Q case and platform requirement to its owner and test. Optional projection consumers also map every OPERATOR obligation. Commit the predecessor/design record.

**Acceptance:** Each selected behavior has one accountable owner, real API or
explicit owner delta, consumer value and native acceptance. No uncommitted
source or open PR alone establishes runtime readiness.

## Packet 2: Qualify native ports and owner capabilities independently

**Files:** Existing owners in PROGRAM-MAP; platform ports; owner test suites.

### Read and native host baseline

- [ ] Qualify native peer and intended-server authentication, bounded decoding, scoped store access, competing-owner fencing, credential custody, boot/incarnation and profile lifecycle. Exercise direct installed IPC clients, including clients other than any optional controller. Refusal must precede protected bytes or effects.
- [ ] Bind authenticated bounded receipt, lineage, usage and revocation reads. Preserve unknown/missing values and provenance. Hook omission/crash remains detect_only; hook success is not a verified native effect.
- [ ] For streaming, qualify S5 Part A then the required Part B source adapters against independent headless consumers. Test audience, stable subscription identity, gap/restore and bounded non-persisting reads. Work and recovery sources wait for their respective owner gates. Do not spend settlement reserve on observation.
- [ ] Qualify time-bound authority for every selected profile through Q31, including read/approval/service credentials and release evidence; execution additionally retains Q12/Q19. Record actual clock/freshness ports and independently refuse revival after rollback or unprovable time.
- [ ] Qualify exact native resource bounds, persistent state/migration, secret/egress and lifecycle ports selected by the profile. Same-user arbitrary consumers require explicit enrollment/custody, not a broadened UID check. Record unsupported resource classes.
- [ ] Pass applicable Q04/Q09-Q13/Q15-Q21 and Q23/Q29-Q31. Pure reads do not acquire W1/M20 or unexposed mutation gates. Any lifecycle or export mutation already exposed must pass Q02 at its actual owner.

### Selected work, authority and control capabilities

- [ ] Qualify passport proof-of-possession/relying-party/lifecycle policy for a passport-selected profile; it grants no effect authority. Qualify recursive delegation at the actual serving path and its supported chain/budget form, including ancestor revocation. Qualify swarm graph head/issuance and accepted-parent joins when exposed (Q24-Q26).
- [ ] Qualify S3 phase 1 and the owner-reviewed focused M20 disposition delta for selected effect/recovery paths. Current authority, exact intent, atomic transition, required persistence and retained uncertainty remain mandatory even before whole S9/S10 redesign completion.
- [ ] Qualify S8 phase 1 kernel stop and S30 reach with native authorization and restart evidence (Q08). Tenant/recovery scopes remain unavailable before their own phases; kernel stop implies no task cleanup without separate custody evidence.
- [ ] Qualify S4/process live cancel/revoke and descendant closure (Q07/Q19). Run the existing `cargo test --locked -p chio-cli --test process_host` at the reconciled owner plus its new live-control cases. Stopped-host admin tests do not prove live control.
- [ ] Qualify W1 original preparation/command/work lookup, evaluator binding and selected recovery using actual current source and dispositions. A missing handle or response never authorizes a replacement dispatch.
- [ ] Qualify S28, production endorsement verification and the actual installed approval route's exact decision/ID binding (Q05/Q06), including direct utility invocation when that component is shipped or exposed. A route without that dependency does not require installing Pi. Native approvals, OS consent and application confirmation remain distinct.
- [ ] Commit each delta in its owner program, then update references and case evidence here. A green consumer mock cannot close an owner gate.

**Acceptance:** Each capability is eligible only after its own native gates. Read,
resource and stop capabilities can proceed independently where their contracts
permit. No requirement to build a workbench or run sealed coding first.

## Packet 2a: Implement native profile qualification and activation enforcement

**Owner:** Existing `crates/tooling/chio-release-evidence`, extending its present
artifact-manifest function through [RELEASE](../specs/2026-10-07-desktop-integration/RELEASE.md).
Current `--verify` proves no Q-case completeness or profile readiness.

**Files:** Existing `src/main.rs`/`Cargo.toml`; proposed `src/lib.rs`,
`src/native_host.rs`, `tests/native_host_qualification.rs` in that crate;
owner-approved versioned catalog/schema; actual native lifecycle/activation
entrypoints recorded by O0/M0 and their Linux/macOS adapters/tests.

**Depends on:** packet 1's selected-profile inventory and native owner contracts.
This implementation precedes O7/M10 activation/promotion tests. Candidate assembly
can precede installed case completion, with unqualified state explicit. Packet
2a source implementation is not itself final candidate qualification. Track
2a-shared (verifier and owner tests), 2a-linux (Linux activation wiring/tests) and
2a-macos (macOS activation wiring/tests) separately. O7 requires 2a-shared plus
2a-linux; M10 requires 2a-shared plus 2a-macos. Neither waits for the other platform.
These are planning completion records, not new runtime or manifest fields.

- [ ] Preserve the existing self-signed artifact manifest and decoder. Implement a distinct versioned native-profile contract and strict bounded verifier over exact candidate inventory, independently authenticated requirement catalog/release policy and authorized evidence. Reuse existing canonical/signature owners, with trust roots provisioned independently of the submitted manifest.
- [ ] Encode required owner/Q/C/platform subcases, positive controls and independent observations. Bind exact capability/deployment tuple, policy/catalog, source/runtime/client artifacts and current validity. Refuse empty-ready, omitted/failed/skipped/unknown evidence, unauthorized exclusions, wrong issuer, stale/revoked records and version/floor rollback. Do not let the submitted result set define which tests are required.
- [ ] Expose the owner-approved typed verifier library and CLI result; document the real command after implementation. It cannot be a caller-provided ready flag or merely a self-signature check. Release eligibility supplies no runtime effect authority.
- [ ] Implement RELEASE's separately authorized qualification-only candidate mode before installed tests: exact candidate/test principal, bounded fixture resources and finite scope, required native predecessor gates, no production route or self-selected test bypass. Qualify cross-mode refusal so installed evidence can be generated before production promotion without a circular gate.
- [ ] Wire the verifier into actual native profile enablement, startup and update/backend/principal/policy activation paths before publication of a protected capability. O0/M0 must name concrete source call sites and tests, including signed-byte/active-generation custody and race-safe rejection. A standalone verifier with no installed enforcement is incomplete.
- [ ] Implement all RELEASE mutation/removal/issuer/decoding/clock/TOCTOU cases at the real owner and native consumers. Use independent route, protected-byte and effect counters; preserve useful passing controls. Existing `cargo test --locked -p chio-release-evidence` remains a regression gate; add the proposed native qualification suite and actual platform activation tests with recorded commands.
- [ ] Register this predecessor in O6/O7 and M9/M10. Installed tests supply exact candidate-bound outcomes after assembly; the implemented verifier then consumes them for promotion. No mock, unbound CLI, manifest hash list or source-only test closes the installed gate. Commit owner implementation and each native consumer in reviewable slices.

**Acceptance:** One concrete shared owner implements evidence completeness and
trusted eligibility. Each platform separately proves actual installed activation
refuses every omitted required case and substituted tuple while a complete
authorized candidate succeeds. Shared implementation completion does not claim
either platform accepted; one platform can promote while the other remains open.

## Packet 3: Bind real native owner interfaces and qualify candidates

**Files:** Existing Rust/SDK/native owner bindings reconciled in packet 1;
proposed installed conformance harness and selected owner schemas.

- [ ] Describe the exact supported capability vector, protocol/ABI versions, profile identity and explicit unavailable outcomes. Use existing L0-L3 contracts and R11 lowering/R12 descent. Create no generic desktop WorkPhase, signer, ledger, scheduler or recovery enum.
- [ ] Reuse canonical owner types and bounded native transports. Correlate full request/response identity, scope/audience, intent, pagination, errors and retry dispositions (Q04). Unknown versions or capabilities refuse without a weaker fallback.
- [ ] Bind resource observations to exact units and native owner enforcement; absent data is unavailable, never unlimited. Freeze frame/queue/verification limits from owner constraints and measured useful controls.
- [ ] Build a direct independent conformance client for the selected owner bindings, with installed negative controls and native effect observers. Maintain private current authority outside application display state.
- [ ] Record provisional candidate acceptance for packet 4 development. Final owner API/ABI freeze follows installed independent consumer acceptance and owning program review; no optional operator schema is a prerequisite.
- [ ] If a shared operator view is selected, follow OPERATOR's separate candidate/freeze matrix over landed owner types. Its absence affects only those consumers. Do not promote it to `spec/OPERATOR.md` or advertise it as stable until its implemented selected-surface acceptance passes.

**Acceptance:** Candidate bindings expose the owner semantics faithfully. Source
or schema validation alone proves neither stable ABI nor native enforcement.

## Packet 4: Prove independent external consumers without Chio UI

**Files:** Existing SDK/application/harness owners plus proposed
`tests/integration/native_host/`; exact consumer paths chosen in packet 1.

- [ ] Record and implement each required integration in FIRST-CLASS-INTEGRATIONS through its existing plugin/launcher owner: Claude Code, Codex, Pi and Hermes, plus Herdr workspace/plugin delivery. Run H01-H08 and I01-I08 as specified for each exact native tuple; keep every missing host/platform cell open. An initial single-host slice can ship independently but cannot close required support.
- [ ] Implement CONSUMERS' installed application and harness scenarios using supported public candidate APIs. Use distinct application logic and domain acceptance; two skins over one application-private controller do not prove reuse. W3's two-application acceptance remains an owner gate, not waived by a CLI probe.
- [ ] Start the selected native profile with workbench, optional operator projection, menu bar and Omarchy shell absent. User-session tests may retain their enrolled login; service-principal tests separately prove authorized unattended operation. Do not infer boot service support from detach.
- [ ] Perform useful work and an actual denied attempt; independently count dispatch, effects, resource charges and disclosure. Demonstrate application scheduling, model/context management and UX remain external while native authority/state stays with Chio.
- [ ] Lose replies before and after native commitment, kill/restart each consumer, race exact and changed-intent duplicates, reauthenticate and query the original identity. Preserve current versus historical authority and six independent W1 observations whenever W1 is selected.
- [ ] Remove/restart the interface during work. Disconnection does not silently cancel or replay; explicit qualified stop and recovery remain reachable through owner routes.
- [ ] Exercise two consumers against shared owner state with no competing authority, nonce, budget or recovery implementation. Qualify all selected source/profile tests and complete installed candidate evidence before freezing the supported owner bindings.
- [ ] Measure integration effort and remaining application code, idle/cold/warm overhead, queue pressure and recovery latency. Record actual measurements and freeze release bounds. Claim no speedup or application-code reduction without a comparable baseline.

**Acceptance:** Independent external consumers perform useful bounded operations
without a Chio frontend. The evidence names which ambition dimensions are
qualified; a read-only or single-owner result cannot claim the complete program.

## Packet 4a: Deliver the existing CLI as a native owner consumer

**Depends on:** packet 3's selected owner candidate, not an operator controller
or workbench. Packet 4 and 4a can develop together; release requires their
applicable installed evidence.

**Files:** Existing `crates/products/chio-cli/Cargo.toml`, `src/main.rs`,
`src/cli/types.rs`, `src/cli/dispatch/mod.rs` and owner-selected modules/tests.
Reconcile exact locations in packet 1; keep the existing `chio` binary. Command
names, flags and a dedicated module are chosen only against landed owner APIs.

- [ ] Inventory promised diagnostic/admin capabilities and their exact owner scopes: reads first; work, resource, approval, stop, recovery and export only when qualified. Missing capabilities are explicit unavailable results.
- [ ] Reuse accepted native owner codecs and authentication. An absent owner, expired profile or unsupported command never falls back to broader legacy CLI privileges. The optional projection is used only for selected view composition; direct owner functionality survives its absence.
- [ ] Define bounded human/machine output and exit behavior for refusal, unavailable, unresolved and completed states. Escape terminal controls and preserve exact security identifiers. Keep credentials out of argv, environment, history and logs; use qualified native/private input paths.
- [ ] CLI confirmation cannot replace required user-presence endorsement or evaluator acceptance. Interruption, pipe closure and noninteractive input cannot silently cancel, approve, resume or resubmit. Reconnect uses original owner identity and fresh native authentication.
- [ ] Run owner-backed parsing, peer/session, stale version, malformed reply, Q04 substitution, terminal injection/literal operand, event-gap and lost-reply tests. Every selected mutation receives Q02 races with native effect/credential observers and useful authorized controls.
- [ ] Compare CLI and independent application reads of the same state, then submit the same authorized native identity concurrently where applicable. Record exact actual test commands once the test exists. A printed fixture does not qualify CLI behavior.
- [ ] Package and invoke the installed binary under the selected native principal. Repeat update, restart/logout, stale-client/server and recovery cases on each platform. Help and public documentation describe only implemented accepted commands.

**Acceptance:** The existing CLI is a useful installed consumer with its own
source/native/cross-client evidence. A QML, Swift or browser shell cannot substitute.

## Packet 5: Prove coordination, shared resources and cooperation

**Files:** Existing process, delegation, swarm, resource, W1-W3, federation and
recovery owners; selected consumer fixtures and independent test observers.

- [ ] Execute the CAPABILITIES/CONSUMERS scenarios for stable process identity, narrowing delegation and current ancestor revocation at the actual serving route. Passport acceptance never bypasses current grants. Record unsupported recursive/aggregate forms explicitly.
- [ ] Concurrently consume a finite shared allowance and mutate a fenced resource from distinct consumers. Restart and retry under original IDs; prove no overspend, stale assignment write, double charge or copied spendable allocator (Q25/Q27).
- [ ] For accepted-result composition, qualify the original evaluator contract, exact parents, producer/task/artifact identity, protected graph head and unique joins. Application task completion or fixture minting cannot advance authority (Q26).
- [ ] Execute unpaid cross-owner work with separate keys, stores, enrolled peers, local policies and refusal on either side (Q28). Distinguish multi-process laboratory evidence from separately administered organizations. Qualify actual W2 service/transport slice; W4/full marketplace completion is not an artificial prerequisite for narrower cooperation.
- [ ] Lose owner/transport responses and result delivery, revoke present access while retaining historical obligations, and reconcile original identities. Evidence, acceptance, settlement and current disclosure stay separate. Funding is optional and adds its rail/finality gates only when selected.
- [ ] For a selected sealed-coding workload, consume its actual harness/resource runner plus W1 and S7 owner evidence. Mini-swe is an optional reference workload and supplies no qualification for a different harness. Qualify both recipe and evaluator boundaries separately; candidate imports/builds/tests cannot access outside files, credentials, direct egress, inherited handles, unrelated processes or the trusted acceptance channel. A known-good evaluator control must pass; failures/unknowns never accept work. Preserve safe capture/export, exact base/artifact review, separately authorized patch application and publication. Native-shell alternate access rejection remains mandatory. Coding qualification cannot be used to skip these cases or block unrelated resource profiles.
- [ ] Close required Claude Code, Codex, Pi and Hermes support separately on Linux/Omarchy and macOS, plus Herdr plugin acceptance for each platform and required harness. Historical Pi, Megastart or mini-swe results cannot qualify another tuple. Preserve Cursor/OpenClaw and all-six acceptance in doc 19 as broader owner-program obligations; completing these four does not close that six-host program.

**Acceptance:** Product claims follow completed dimensions and exact capabilities.
No synthetic green UI, application ledger or fixture signature can supply a
native authority fact. Full ambition acceptance includes coordinated work,
shared resources and independent-owner cooperation.

## Packet 6: Package native services and optional consumers

**Files:** [Omarchy/Linux plan](2026-10-07-omarchy-integration/IMPLEMENTATION.md)
and dependent macOS plan at
`docs/superpowers/plans/2026-10-07-macos-integration/IMPLEMENTATION.md`.

- [ ] Build signed/reproducible candidates for the selected native profile after required owner/consumer evidence. Candidate assembly precedes installed qualification. No workbench/projection dependency may enter the baseline through packaging.
- [ ] Run the complete selected-profile case manifest, installed CLI/harness/application tests and native lifecycle/update/rollback/removal acceptance. Test case removal, tuple substitution and authenticated malformed evidence; none may promote a profile. Exclusions require explicit owner approval and capability absence.
- [ ] Package and qualify the required Herdr plugin against installed required harnesses without making it mandatory for headless activation. Preserve its existing app contract and authentic owner state across close/reopen/unlink.
- [ ] Keep optional workbench/QML/Swift/notifications in an independent lane. Selected views consume native owners or the qualified optional projection. Preserve complete OPERATOR/Q17 browser, origin, privacy, accessibility, correlation and exact approval gates; close inherited workbench findings before shipping that client.
- [ ] Verify native service identity, current credentials, package/architecture, migration/floor and single-writer custody after upgrade/reboot. No unsigned, stale, downgraded or missing backend may start an unconfined fallback.
- [ ] Measure host resource bounds and preserve a qualified owner stop/recovery route when any UI is unavailable. Distinguish user unenrollment from authorized all-user removal and retained evidence custody.
- [ ] Verify public revision/artifact availability separately from native acceptance. Record owner source, local, native, hosted checks, external-operator participation, public release and documentation review as separate dimensions.

Boundary-interactive and managed-endpoint features retain their deferred native
gates. Omarchy configuration repair, compositor tools and a desktop authority
implementation remain out of scope. New resource backends or consumers enter
through the same owner and evidence discipline.
