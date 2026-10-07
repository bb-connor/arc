# macOS Desktop Operator Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a thin Mac client and qualified platform adapters for the shared desktop operator program, with sealed W1 work as the first execution product.

**Architecture:** One C-layer controller outside the TCB projects existing work, recovery, events, identity and stop owners. The browser workbench comes first; CLI and menu bar clients use the same projection. Thin Seatbelt or evaluated VM adapters deny ambient access while Chio's native owners grant authority.

**Tech Stack:** Existing Rust kernel/process/security crates, existing workbench, existing Python mini-swe integration, Pi restricted launcher/model relay, Swift/AppKit or SwiftUI and ServiceManagement for the Mac shell, and exact selected isolation runtime.

**Spec:** [macOS annex](../../specs/2026-10-07-macos-integration/ANNEX.md), [shared desktop program](../../specs/2026-10-07-desktop-integration/README.md), [ADR-0038](../../../adr/ADR-0038-desktop-operator-program.md), [operator projection](../../../../spec/OPERATOR.md), [program map](../../../architecture/PROGRAM-MAP.md), and [qualification](../../specs/2026-10-07-desktop-integration/QUALIFICATION.md).

## Global constraints

- `runtime_evidence: unavailable` applies to every work packet in this plan. No implementation/test step below has been run by writing it.
- Isolation denies; Chio grants. The controller is outside the TCB and a separate process from gateway and host.
- Workbench first; CLI and menu bar thin clients; Finder Services secondary.
- The first execution product is a sealed, single-owner, unpaid W1 work commitment.
- All six doc 19 hosts remain in scope: Claude Code, Codex, Cursor, Hermes, Pi, and OpenClaw. Pi first by evidence; qualification is per exact host tuple.
- Hook-mode sessions are `detect_only`. Native-shell workspace effects are `cannot_see`; only gateway-routed or adapter-routed MCP calls authorized before dispatch can be `prevent`.
- No new recovery, work/task, credential, approval, event or stop contract. Missing owner APIs block dependent implementation.
- Approval requires S28 roster, production approval-path integration/qualification of the existing passkey verifier, fixed installed Pi approval utility and exact intent binding. Per-task stop is S4 closure; S8 phase 1 is the durable Kernel stop scope, not the later Tenant/Recovery phases.
- `native-descendant-v1` is retired. Seatbelt cannot substitute for its former ES/NE and independently qualified network-containment gates.
- ES/NE managed endpoint is a separate deferred track.
- The initial app build experiment uses Apple silicon arm64 and `MACOSX_DEPLOYMENT_TARGET=15.0`; backend minima and supported release tuples are separate.
- No runtime implementation starts from this documentation-only consolidation. Execution begins with the authorized dependency packet and its source reconciliation.
- No em dashes; preserve unrelated working-tree changes; public copy links only public Chio source and revisions verified there.

## Review focus

- A stale/forged same-user IPC peer after service restart must not inherit the previous peer's custody (M1).
- A lock or fast-user-switch event lost during review must not disclose a task or preserve a stale actionable review (M2/M3/M8).
- A native shell can use inherited descriptors, descendants or delegated services to bypass a simple executable/path policy (M4/M5/M7).
- A lost reply during artifact export or an interrupted upgrade can duplicate an effect or revive stale authority (M6/M8/M9).
- A path with Unicode/case collisions, symlink swaps or oversized archive expansion must not escape intake/export scope (M6/M8).

---

## Source map and gate discipline

The [program map](../../../architecture/PROGRAM-MAP.md) owns predecessor retrieval and exact pins. This plan was checked against source objects available on 2026-10-07, not a merged runtime. `origin/integration/process-security-m4` supplied the security/process paths below, `origin/feat/agent-workbench` supplied workbench paths, and public Pi `4214a5a8ddec776a5ff9ec78007442683fd8df03` supplied launcher paths. These are research locators, not public checkout instructions or immutable implementation baselines. Record the integrated source revision before execution.

| Existing source target | Responsibility retained |
| --- | --- |
| `crates/security/chio-secure-ipc/src/{lib,credentials,tests}.rs` | Peer authentication, local endpoint/descriptor custody and framing |
| `crates/kernel/chio-process/src/{registry,worker,security}.rs`, `src/worker/unix.rs`, `tests/{processes,host_routes,crash_recovery,worker_protocol}.rs` | Process/child identities, control and lifetime |
| `crates/products/chio-cli/PROCESS_HOST.md` | Process host control and documented limitations |
| `crates/security/chio-secret-broker/src/{backend,daemon,authority_ipc}.rs` | Native secret custody and dispatch |
| `crates/kernel/chio-kernel/src/{approval,custody}.rs` | Native approval verification and passkey capability boundary |
| `sdks/python/chio-mini-swe/src/chio_mini_swe/{repository,repository_archive,repository_container,repository_proof,repository_review,repository_scope,repository_snapshots,operator_native}.py` | Existing coding resource, capture, runner, review and export |
| `sdks/python/chio-mini-swe/tests/test_{repository,repository_container,repository_review,repository_scope,repository_snapshots,repository_import,operator}.py` | Reuse runner and artifact regression suites |
| `crates/products/chio-workbench/src/{engine,kernel,model,web}.rs`, `web/{app.js,index.html,style.css}`, `tests/workbench.rs` | First browser surface, task/worktree/review UX |
| Public Pi repository `src/{protected-cli,sandbox,model-relay}.ts` | Restricted session launch, Seatbelt policy, native model path |
| `docs/strategy/chio-direction/19-priority-agent-integrations.md` | Host contract and I01-I08 |

Proposed files below do not exist on the inspected implementation baseline. They are scoped additions after their dependencies land, not claimed APIs:

| Proposed target | Responsibility |
| --- | --- |
| `crates/products/chio-operator/` and `tests/integration/operator/` | Shared controller/projection, created by the shared program, not a second Mac controller |
| `integrations/macos/Package.swift` | Mac shell and platform test targets only |
| `integrations/macos/Sources/ChioMenuBar/{App,ServiceStatus,OperatorClient,ReviewNavigation,FinderServices}.swift` | App composition, service UI, shared protocol client, workbench review navigation and untrusted Finder selection handoff |
| `integrations/macos/Tests/ChioMenuBarTests/{ServiceStatusTests,OperatorClientTests,FinderServicesTests,PrivacyTests,PackageAdmissionTests}.swift` | Mac presentation, selection validation, package rejection and lifecycle tests |
| `integrations/macos/packaging/` | Bundle/entitlement inventory, signing/distribution scripts and update/removal integration |
| `integrations/macos/tests/` | Installed-system probes and independent observers, not a parallel authority implementation |
| `docs/superpowers/specs/2026-10-07-macos-integration/evidence/` | Source reconciliation and candidate reports produced only when the named experiments run |

Each packet is a reviewable deliverable, composed of small checkbox actions. For changes to a landed owner, first add the specified failing regression in its existing suite, run the named package command and retain failure, implement the minimum owner-approved delta, rerun and retain success, then review/commit that packet. Do not invent test source using unlanded W1/S5/S8 methods. M0 records the actual owner signatures and test entrypoints before later packets are expanded into code-level execution tasks. A blocked packet produces a precise dependency gap, not a mock substituted for qualification.

### M0: Reconcile dependencies and freeze the execution tuple

**Fields:** `boundary_class: advisory_only`; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** accepted ADR-0038 and the shared program map. This packet can execute as source/plan reconciliation; it enables no effects.

**Files:** Read the shared owners above and `spec/OPERATOR.md`. Create `docs/superpowers/specs/2026-10-07-macos-integration/evidence/dependency-reconciliation.md` only after doing this inspection. Modify this plan with actual source locations if upstream paths changed.

**Interfaces:** Consume actual landed owner contracts. Produce a source/API/test map and dependency disposition; no new method names, wire types or runtime schemas.

- [ ] Record the implementation worktree revision and inspect tracked source, without assuming an open proposal is merged:

  ```bash
  git rev-parse HEAD
  git status --short
  rg --files crates sdks spec docs/strategy | rg 'chio-(secure-ipc|process|secret-broker|workbench|mini-swe|operator)|19-priority-agent|OPERATOR.md'
  ```

- [ ] Read each selected owner and record the exact symbols exported for W1 views/commands, original-operation recovery, stable subscriptions, S28 identity, S4 closure, S8 stop and S7 backend evidence. Use:

  ```bash
  rg -n 'WorkHandleV1|WorkViewV1|WorkClient|WorkTransport|InspectWorkflow|SubmitApproval|ResumeWorkflow|CancelWorkflow' crates sdks spec
  rg -n 'PeerIdentity|SecureUnixListener|PasskeyCapabilityVerifier|ProcessRegistry' crates
  ```

- [ ] Close the dependency matrix explicitly: security/process foundation; S3 phase 1; S5 Part A and Part B; S9 M20; S4 phases 1/2; S8 phase 1/S30; S28 roster (S8 phase 3); live host cancel/revoke; installed approval utility repair; production integration/qualification of the existing `PasskeyCapabilityVerifier`; recovery P1 fixes; W1. Record which packets need which prerequisite. Tenant stop phase 4 and Recovery stop phase 5 are not silently included in phase 1.
- [ ] Confirm recovery inspection no longer drains settlement reserve under repeated read-only observation. Require the recovery owner's failing-then-passing regression and actual integrated test command. Do not write a Mac polling workaround.
- [ ] Confirm the shared controller uses a separate process and the projection does not redefine owner commands. Confirm S7 admits proposed Seatbelt/Mac VM evidence kinds before enabling those backends.
- [ ] Review the source record against the shared qualification envelope; mark each absent item unavailable. Commit only the reviewed source/plan reconciliation through the executing branch's normal workflow.

**Acceptance:** A reviewer can find every consumed symbol at the recorded revision and distinguish current source, accepted design and missing runtime evidence. A deliberately absent dependency blocks its packet. NK-01 to NK-03, W2-W4, M11 and witness topology are not blanket gates.

### M1: Add Darwin transport custody to `chio-secure-ipc`

**Fields:** `boundary_class: prevent` at authenticated IPC admission; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** M0 security foundation and shared operator transport contract. No approval or execution qualification follows from this packet alone.

**Files:** Modify `crates/security/chio-secure-ipc/src/lib.rs`, `src/tests.rs`, and `Cargo.toml` only if the selected supported binding needs it; add a narrowly scoped Darwin module in that crate. Preserve `src/credentials.rs` Linux systemd/memfd semantics rather than marking them portable. Test in the crate's existing suite plus a proposed `tests/darwin_peer_custody.rs`.

**Interfaces:** Consume existing `PeerIdentity`, `SecureUnixListenerConfig`, listener/custody and framing interfaces. Any transport or peer-incarnation extension is reviewed at this owner before shared clients consume it. `getpeereid` alone cannot fabricate the existing nonzero process identity.

- [ ] Inspect current platform refusal and Linux credential logic with `rg -n 'target_os|peer|SO_PEERCRED|process_id|lifecycle|inode' crates/security/chio-secure-ipc/src`.
- [ ] Record a Darwin API decision using actual supported SDK/binding facts: authenticated AF_UNIX with complete required peer facts, or XPC within this crate's abstraction. Specify exactly which facts are kernel-supplied, which are authenticated enrollment, and which cannot be established. Reject incomplete identity rather than weakening checks.
- [ ] Add failing cases: wrong user; same-user wrong process; caller-supplied identity spoof; stale peer after restart/PID reuse; socket/path replacement; non-private parent; oversize frame; inherited descriptor leakage; missing credential facts. Expected result for each is refusal before a protected frame is accepted.
- [ ] Run and retain the pre-change failure on Darwin:

  ```bash
  cargo test -p chio-secure-ipc
  ```

- [ ] Implement the smallest Darwin custody path and retain the same command's passing output. Run the existing Linux suite on Linux to prove platform-specific credentials were preserved; a Mac pass does not qualify Linux.
- [ ] Exercise two real separate test processes and two users, including endpoint replacement during reconnect. Verify successful same-tuple operation plus all negative cases; review and commit the owner change with its API record.

**Acceptance:** Kernel-authenticated peer/custody evidence exists for the selected Mac path; forged, ambiguous, stale or replaced peers cannot act. No private protocol fork or unauthenticated fallback appears.

### M2: Connect the thin Mac shell to the shared controller

**Fields:** `boundary_class: advisory_only` for UI; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** M1; shared controller; S5 Part A/B; browser workbench consumer. Mutating controls stay unavailable until M3/M6 gates close.

**Files:** Create the proposed Mac Swift package and five shell source files in the source map; create `ServiceStatusTests.swift`, `OperatorClientTests.swift` and `FinderServicesTests.swift`. Add the proposed bundle `integrations/macos/packaging/Info.plist` with its `NSServices` entry and proposed installed handoff cases in `integrations/macos/tests/finder-services-cases.md`. Consume shared `crates/products/chio-operator/` and `tests/integration/operator/`; changes to those remain shared-program changes. Do not create `chio.desktop.operator.v1` or `chio.omarchy.operator.v1`.

**Interfaces:** Consume the delivered `chio.operator.v1` projection and source-generated types from M0; produce rendered views/navigation, OS service-status observations and untrusted selection proposals. Only the authenticated existing intake owner may capture a proposed selection and return native resource identity; no service callback creates authority.

- [ ] Capture a workbench session on Mac using its existing surface: list independent W1 observations, inspect a receipt, open recovery and view artifact review. Record unsupported actions as unavailable before adding a shell.
- [ ] Write UI fixture cases for absent owner, stale view, hook `detect_only`, native-shell `cannot_see`, gap/reconnect, mixed generations, 200 tasks, keyboard navigation and screen-reader names. Assertions check rendered labels and disabled actions, not a duplicated authority state machine.
- [ ] Create the Swift package's shell/test targets and run its failing tests with `swift test --package-path integrations/macos` after that manifest exists. Record package/toolchain identity.
- [ ] Implement menu bar status, launch/open-workbench, authenticated shared-client observation, and `SMAppService` state presentation. Use an existing shared CLI command when present; add a thin client at the CLI owner only if its delivered projection lacks that entrypoint. No invented CLI command is assumed here.
- [ ] Implement the secondary Finder Services entry in `FinderServices.swift`, advertised by `NSServices` and registered through `NSApplication.servicesProvider` only when the handler is ready. In `FinderServicesTests.swift`, parse the supplied `NSPasteboard` as file URLs with `readObjects(forClasses:options:)`; accept a single bounded local project selection as an untrusted proposal, reject empty/multiple selections, non-file URLs, unsupported objects, malformed/oversized data, and never interpret filenames as commands. The handler passes the proposal to the shared authenticated intake owner recorded in M0; it cannot infer access from pasteboard origin, capture contents itself, issue a grant or start work. Denied/unavailable intake, path replacement and symlink escape produce no resource capture or authority. Use generic failure text without leaking the path. [Apple service declaration](https://developer.apple.com/documentation/bundleresources/information-property-list/nsservices), [service provider](https://developer.apple.com/documentation/appkit/nsapplication/servicesprovider), [pasteboard reading](https://developer.apple.com/documentation/appkit/nspasteboard/readobjects(forclasses:options:)).
- [ ] Add lock/user-switch tests that clear sensitive cached display even during reconnect; disable stale review navigation, show generic notifications and reacquire current native session authority before sensitive release.
- [ ] Run the Swift suite and shared operator integration command recorded in M0; inspect the running Mac app with mouse, keyboard, VoiceOver, large text and dark/light appearance. Verify loss/restart does not recreate work, then review/commit this client packet. M2 source/unit completion enables M9 candidate assembly; final Finder acceptance runs against that clean installed signed candidate under M9 and gates M10, so no packaging dependency cycle is introduced.

**Acceptance:** Workbench remains the full review client, the Mac shell is useful without execution permissions, and backend/controller/authorization states are distinct. The shell cannot sign, issue grants or keep a competing task ledger.

### M3: Expose attributable approval and truthful stop

**Fields:** `boundary_class: prevent` at native approval/closure; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** M0-approved S28 roster, production approval-path integration/qualification of the existing `PasskeyCapabilityVerifier`, repaired installed Pi approval utility, S4 phases 1/2, S8 phase 1/S30 and live process-host cancel/revoke; M2. Each is a hard gate, not work delegated to Swift.

**Files:** Review native owners `crates/kernel/chio-kernel/src/approval.rs`, `custody.rs`, `crates/kernel/chio-process/src/registry.rs`, `tests/host_routes.rs`; extend existing native tests only at those owners. Modify shared operator integration cases and Mac `ReviewNavigation.swift`/`OperatorClientTests.swift` as presentation consumers.

**Interfaces:** Consume delivered roster/approval/closure command and result types recorded in M0. Produce UI requests referencing exact native intents; native signatures and closure evidence remain owner-produced.

- [ ] Inspect the installed Pi utility provenance and its owner regression, not only the TypeScript wrapper. Require deny, mismatched approval ID, mismatched requested decision, stale/expired response, and valid matching approval cases; retained credential count must be zero for every rejected case.
- [ ] Require a real production passkey verification path against an enrolled roster identity. Test unknown/revoked operator, wrong audience/intent, stale challenge, replaced resource digest/destination, and user cancellation. Generic Touch ID success must fail as an approval input.
- [ ] Extend the shared projection/UI cases: show exact native intent and artifact/destination digest; change the native intent after rendering; submit the old review. Expected: no effect and invalidated review, with original operation custody retained.
- [ ] Test per-task closure while an unrelated task runs, with a live child and delayed remote response. Expected: S4 scope contains the intended task family; other work remains separate; fence, process termination and external outcome are shown distinctly.
- [ ] Test S8 Kernel stop across service restart/reboot and assert current-generation requirements before resume. Do not label Tenant or Recovery stop available from phase 1 evidence. A missing closure result remains unresolved rather than synthesized success.
- [ ] Run native commands identified in M0 plus `cargo test -p chio-process --test host_routes` on the integrated source and `swift test --package-path integrations/macos`. Independently count effects and surviving incarnations, review and commit client changes only after all owner gates pass.

**Acceptance:** Approval is attributable to the native roster identity and bound to the exact reviewed action; stop reports the owning contract's scope and uncertainty. No desktop signoff or “killed PID” shortcut closes either gate.

### M4: Qualify the lower-assurance Seatbelt adapter

**Fields:** `boundary_class: prevent` for mediated routes, `cannot_see` inside native workspace execution; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** M1; S7 Seatbelt kind; process custody and broker/relay integration. M3 is required before approved effectful work. Use the current restricted launcher as an owner input.

**Files:** Public Pi repository `src/sandbox.ts`, `src/protected-cli.ts`, `src/model-relay.ts` and existing launcher/model-relay tests; changes belong to that repository. Create `integrations/macos/tests/seatbelt_cases.md` and an installed-probe driver only after selecting the existing launcher test entrypoint. Record results in the shared qualification envelope.

**Interfaces:** Consume the actual launcher profile and native routes. Produce S7 evidence through its owner, including policy/runtime/OS identity and denial observations. No new grant broker.

- [ ] Re-read the exact pinned public launcher and package manifest; record current installed executable/library closure and the policy hash. Resolve public release availability independently of local sibling checkouts.
- [ ] Pin two distinct cases: restricted session with fork denied; proposed shell-capable boundary session with descendants permitted under equivalent restrictions. Do not qualify the latter using the former's evidence.
- [ ] Run an allowed useful task and verify file result externally. Add a deliberately forbidden outside-workspace read/write, keychain/credential access, policy modification and alternate-executable attempt; require no forbidden effect, not just a denial log.
- [ ] Probe symlink/path replacement, inherited file/socket handles, IPv4/IPv6/TCP/UDP/direct DNS/loopback destinations, Unix sockets, reparented children and delegated services. Fork-denied sessions must reject creation; descendant-allowing sessions must retain confinement. Record uncovered routes as failure.
- [ ] Kill gateway, model relay, launcher and controller separately; corrupt the policy and change runtime library paths. Expected: no unsandboxed launch/retry, no raw secret exposure, unavailable affected profile and truthful existing-effect uncertainty.
- [ ] Run the existing plugin build/test/probe commands read from its pinned manifest, record exact commands and real effect oracles, then review/commit only necessary thin-adapter changes at their owners. Promote no desktop profile until I08 and distribution packets pass.

**Acceptance:** Seatbelt is an explicit lower-assurance S7 backend with measured denial/descendant scope, without general sandbox rewrites. The source's existing `sandbox-exec` use is preserved as evidence; no unsupported claim of current full desktop qualification follows.

### M5: Select an existing higher-assurance VM runtime

**Fields:** `boundary_class: prevent` at Chio-owned routes, `cannot_see` inside guest shell effects; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** S7 Mac VM evidence amendment, M0 owner map, M1 and process/broker/relay integration. This packet selects a runtime before adapter implementation. Bespoke VZ work needs a fit-gap decision.

**Files:** Read the pinned upstream Apple/OpenShell sources in [platform research](../../specs/2026-10-07-macos-integration/research/apple-platform.md). Add proposed `integrations/macos/tests/vm-output-cases.md` and `vm_output_probe.py` for the synthetic producer/independent observer; record their actual invocation after implementation, not an invented runtime command. Create `evidence/vm-runtime-selection.md` under the Mac spec only after experiments. Reuse the mini-swe runner owner and selected runtime adapter location established at M0; do not create a Mac guest supervisor by default.

**Interfaces:** Consume existing runtime lifecycle and owner coding-resource contracts. Produce one evidence-backed selection with rejected alternatives/reasons and an S7 owner amendment. Runtime approval UI or policy must not become Chio's grant authority.

- [ ] Resolve immutable candidate releases and source/image hashes, licenses, supported SDK/OS, signature/entitlement needs and update path. Keep Apple Containerization's macOS 26/Xcode 26 row separate from the app's macOS 15 experiment.
- [ ] On the same Apple silicon test machine and fixed synthetic repository, boot Apple Containerization and OpenShell MicroVM candidates separately. Record exact commands from each pinned source's supported example; do not install both into a user's ordinary environment or select a runtime automatically.
- [ ] For each candidate, complete the same mini-swe fixed recipe through kernel-owned routes. Verify no direct egress, host writable share, credential mount, management socket or unexpected device. Test guest-to-host channel impersonation and launch-generation substitution.
- [ ] Before selection, freeze finite output limits in the candidate experiment: retain at most 8 MiB combined stdout/stderr per work item; allow at most 1 MiB per bridge frame, 4 MiB queued bridge bytes and 64 queued frames per VM; limit aggregate guest output ingress to 1 MiB/s sustained with a 2 MiB burst. These are proposed experiment ceilings, subordinate to stricter native owner limits, not claims about current APIs. Check declared frame length before allocation. In `vm_output_probe.py`, exercise a valid useful workload below the caps and valid boundary-size payloads, then exceed each byte/rate/queue cap separately and flood stdout, stderr and bridge traffic concurrently at 4 MiB/s for 60 seconds with a deliberately stalled consumer. Include an oversized declared frame and an unterminated line. The independent observer must show retained bytes, queue depth, memory and disk remain bounded, with explicit truncation/drop counts or owner-directed termination. Truncate display/log payload only; never truncate an authoritative message into a valid command/result. Protocol overflow refuses/closes that route and requests owner stop/reconciliation; retain original custody and report unresolved closure/outcome until proved. A candidate that loses custody, silently drops authority messages or cannot enforce the limits fails selection even if ordinary benchmarks pass.
- [ ] Kill supervisor/runtime/controller at launch, operation dispatch, output capture and stop. Observe surviving processes/VMs, remaining channels and outside effects. Test sleep/wake, reboot, storage exhaustion and image mismatch. Lost replies resolve under the original native operation.
- [ ] Measure cold/warm start, useful-task completion, CPU/RSS/disk/energy and stop closure with raw data. Reject a candidate that cannot maintain Chio authority or independent custody even if its benchmarks are faster.
- [ ] Write the selection report and narrowly scoped adapter task with actual upstream signatures. If neither fits, retain VM unavailability and document exact gaps before separately approving a bespoke VZ adapter. Review/commit the decision and minimum adapter only after that review.

**Acceptance:** A runtime selection is supported by same-workload installed evidence and independent denial/closure oracles. Vendor documentation is source evidence; no unconditional Apple/OpenShell winner or generic VM security claim appears.

### M6: Deliver sealed W1 work through existing runner and workbench

**Fields:** `boundary_class: prevent` at kernel-owned tools, `cannot_see` for internal shell effects; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** W1 plus recovery fixes and owner commands from M0; M3; qualified M4 or M5 backend; existing mini-swe/Pi coding resource and browser workbench. W2-W4 are outside this packet.

**Files:** Modify existing mini-swe `repository.py`, `repository_scope.py`, `repository_archive.py`, `repository_snapshots.py`, `repository_container.py`, `repository_review.py`, `repository_proof.py`, `operator_native.py` only where the Mac cases require changes. Extend the corresponding existing tests. Modify workbench `src/model.rs`, `src/web.rs`, `web/app.js`, `tests/workbench.rs` through its owner to render W1 projections and review artifacts.

**Interfaces:** Consume actual W1 single-owner commitment and independent `WorkViewV1` observations. Reuse `sandbox/execute`, worktree/capture and export owners. Add an independent acceptance oracle there; no desktop-private task or result model.

- [ ] Record a fixed synthetic recipe, captured source digest, input/dependency closure, budget, oracle identity and acceptance rules in the existing runner fixture format. Use a small repository with both known-good and deliberately wrong candidate patches.
- [ ] Add failures in existing artifact suites for symlink/hardlink traversal, Unicode/case collisions, special files, archive expansion/entry limits, replaced captured base, wrong artifact digest and changed export destination. External destination inventory must remain unchanged for every rejected case. In existing `tests/test_repository.py` and `tests/test_repository_review.py`, stage an approved export to an absent path, pause immediately before final publication, and have an independent process create an ordinary sentinel file at that same path. The native publication owner must use an atomic no-replace operation bound to the reviewed parent/target identity and expected absence, not an existence-check followed by overwriting rename/write. Reject publication, preserve the sentinel bytes/digest, retain the original operation outcome and produce no delivered-success claim. Pair with an absent-path success control. Overwrite is a separate native intent binding the existing target identity/content and exact replacement artifact; test explicit valid overwrite and a second target mutation that must refuse. Repeat the same-path race during recovery/retry to prove a lost reply cannot bypass the no-replace condition.
- [ ] Run the relevant existing suites before implementation from the integrated mini-swe directory:

  ```bash
  uv run --extra dev pytest tests/test_repository.py tests/test_repository_scope.py tests/test_repository_import.py tests/test_repository_review.py tests/test_repository_snapshots.py
  ```

- [ ] Extend the existing resource/runner/review path minimally; keep input capture and oracle outside agent-writable custody. Render diff/content as text, never executable project HTML/Markdown or automatic script invocation. Acceptance is evaluator-derived and recorded by the W1 owner; human apply/export approval cannot set an acceptance boolean or override a rejected evaluator result.
- [ ] Run Pi first through W1 using a real selected backend. The independent oracle accepts the correct patch and rejects the plausible wrong patch. Test accepted-but-undelivered, execution-complete-but-rejected, interrupted execution with retained artifact and unknown external result as separate view cases.
- [ ] Drop create/approval/export replies and restart components. Recover original operation identity and independently prove no duplicate export/apply or task submission. Run the suites above, `cargo test -p chio-workbench --test workbench`, and recorded W1/recovery owner tests. Review/commit the integrated sealed-work packet.

**Acceptance:** A user can submit fixed work, see attributable history, inspect the result, obtain independent acceptance and explicitly deliver the artifact. Arbitrary agent-written scripts cannot grant acceptance; valid authorization alone cannot masquerade as result proof.

### M7: Qualify selected hosts and interaction profiles separately

**Fields:** `boundary_class: prevent` for protected mediated tools; `prevent` at routed boundary calls and `cannot_see` for native-shell workspace effects; hook observation `detect_only`; `planning_status: ready_after_adr` for protected interaction and hook observation, `planning_status: deferred` for boundary interaction with native shell; `runtime_evidence: unavailable`.

**Depends on:** M4/M5 backend, M3 authority and stop, doc 19 qualification procedures, host-specific implemented integration (including M6 where sealed work is selected), and M9's signed candidate for final I08. I01-I08 are this packet's qualification outputs, not prerequisites already assumed passed. Hook observation can ship under M2 without this packet's prevention claim.

**Files:** Read `docs/strategy/chio-direction/19-priority-agent-integrations.md`; extend each host's existing restricted-launcher and integration suites at the source locations recorded in M0. Create no generic six-host wrapper. Record per-host evidence under the shared qualification owner.

**Interfaces:** Consume the same work/authority routes. Produce six independent exact host/adapter/runtime/OS qualification cells, each with explicit sealed, protected or boundary interaction profile. Sealed-work hosts require applicable doc 19 I01-I08 evidence too. Any inapplicable subcase needs an explicit doc 19 owner disposition for that exact surface; the desktop cannot waive gates, and every shipped host integration requires I08.

- [ ] Inventory built-in tools, plugins, MCP routes, shell, alternate network SDKs, extensions and delegation for Claude Code, Codex, Cursor, Hermes, Pi and OpenClaw from each pinned host. Start with Pi; leave untested cells unavailable.
- [ ] For protected mode, remove native shell and direct tools instead of relying on hook denial. When the deferred boundary track is explicitly opened, deliberately retain native shell and show internal effects as `cannot_see`. For hooks, force hook failure/omission and confirm the UI still labels `detect_only`.
- [ ] Execute I01 installation/version discovery, I02 useful work and I03 forbidden effects/alternate routes using each real host. A blanket-deny profile fails useful work.
- [ ] Execute I04 owner absence/death/malformed reply/loading failure, I05 wrong/expired/revoked authority and budgets, and I06 request/result/signer substitution against independent effect observers.
- [ ] Execute I07 retry, live cancellation, resume, concurrent work and restart with original identity; run I08 using the exact signed candidate assembled and made available by M9, including upgrade/removal and overhead. Exercise unqualified profiles only inside the controlled qualification harness; they stay disabled for ordinary use. Earlier I01-I07 evidence does not substitute for I08.
- [ ] Record the exact passing and failing candidate cells and review/commit host changes at their owners; hand passing cells to M10 for release promotion. Six-of-six remains the program target; one-host success is reported as one host.

**Acceptance:** Each interactive claim names its exact control point and host tuple. No native-shell workspace write is represented as individually authorized or receipted.

### M8: Close Mac lifecycle, privacy, artifact and retention cases

**Fields:** `boundary_class: prevent` at owner-controlled release; `advisory_only` for diagnostics/UI; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** M2 for every delivered profile, including observation-only; M3 only for approval/stop cases; M6 only for implemented task/artifact cases. Privacy and sensitive-session lifecycle checks are mandatory for every delivered profile and cannot be skipped or blocked merely because M6 is not selected. Reuses native storage, recovery and export owners.

**Files:** Mac `PrivacyTests.swift`, service/client source, existing mini-swe artifact suites, workbench review renderer, and owner evidence export code `crates/kernel/chio-kernel/src/evidence_export.rs` / `crates/platform/chio-store-sqlite/src/evidence_export.rs`. Create proposed installed-system `integrations/macos/tests/session-lifecycle-cases.md` covering restored menu bar and workbench state; extend `PrivacyTests.swift`, `OperatorClientTests.swift` and existing workbench `tests/workbench.rs` for stale-view/action rejection.

**Interfaces:** Consume existing protected storage/export and closure contracts. Produce bounded diagnostics, honest redacted views, local export inventory and lifecycle evidence; no credential store in the UI.

- [ ] Seed unique synthetic canaries in credentials, prompt, source, path, URL, untrusted errors, task names and identifiers. Exercise success, denial, crash, lock, user switch and reconnect; scan app/OS logs available to the tester, argv/env, notification/screen captures and default export members. List unobservable OS surfaces instead of calling them cleared.
- [ ] Enforce annex retention/time-size bounds through existing owners; retain unresolved custody and required proof dependencies. Fill disk/queues and advance test time; required persistence failure must block effect dispatch while diagnostic loss is counted.
- [ ] Build a support export with exact preview, local destination and 10 MiB cap. Feed traversal/symlink members, raw database/WAL, credentials and secret-bearing payloads; reject forbidden output and verify no network transmission.
- [ ] Tamper with signed evidence bodies and omit referenced payloads. Native verification rejects tampering; presentation reports omissions and never marks a redacted derivative as the original signed object.
- [ ] Test sleep/wake, logout, fast user switch and full reboot at review, dispatch, stop and export for each implemented surface. After reboot/login, restore both menu bar state and workbench browser tabs with a previously actionable review; delay or deny owner/session/freshness reconciliation. Sensitive contents stay cleared and affected actions remain unavailable, and submitting the old review from either client produces no approval dispatch, export or effect. Independent screen/notification capture, native dispatch records and external effect counters must agree. Fresh reconciliation may restore only current owner views; unknown pre-reboot effects stay unknown under the original operation, not redispatched. Observation-only runs still test rebooted stale views and disabled absent mutations without depending on M3/M6; approval-only runs include native approval cases without M6. Repeat with a dropped OS lifecycle observation to prove conservative startup reconciliation.
- [ ] Run changed owner suites plus `swift test --package-path integrations/macos`; review the deletion inventory and raw external observer data, then commit the scoped fixes.

**Acceptance:** Privacy is enforced before persistence, artifact safety is checked at the existing owner, and lifecycle uncertainty neither discloses data nor manufactures closure.

### M9: Assemble and evaluate the signed distribution candidate

**Fields:** `boundary_class: advisory_only` for distribution checks; `prevent` at native admission during transition; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** M1/M2 implementation for an observation-only candidate; M3 additionally only when approval/stop is included; implemented M4/M5/M6 components and host integration composition for profiles actually included. Completed M7 host qualification is not required to assemble, sign, notarize or publish a clearly labeled qualification candidate. Unqualified profiles remain disabled outside the controlled harness. Entitlement-gated enterprise components stay excluded unless the independently opened M11 track supplies its implementation and required eligibility. M10, not this packet, enables qualified release profiles.

**Files:** Create `integrations/macos/packaging/{README.md,component-inventory.md,release-checks.sh}` and supported signing/update/removal integration after the actual bundle target exists. Create `integrations/macos/tests/{distribution-cases.md,package-admission-cases.md,credential-rollback-cases.md,performance-cases.md}` and proposed `integrations/macos/Tests/ChioMenuBarTests/PackageAdmissionTests.swift`. Use the existing native credential-owner regression suite identified in M0 for restore/freshness assertions; retain exact owner test commands in the generated report. Publish results in the shared qualification envelope, not a new Mac authority schema.

**Interfaces:** Consume implemented component bytes, native compatibility/fencing and platform service APIs. Produce immutable signed/notarized candidate bytes, a candidate inventory, installation/update/removal/performance evidence, and controlled availability for M7. Produce no production supported-profile allowlist.

- [ ] Freeze the candidate inventory, payload closure, entitlement review and annex thresholds before tests. Record each proposed OS/CPU/runtime row, explicit excluded rows, unsigned/final byte identities and provisioning identity. Set unqualified profiles disabled for ordinary use in the candidate configuration.
- [ ] Build/sign nested components using the reviewed identity and minimal entitlements, notarize through Apple's supported workflow, inspect the notary log and staple the ticket. With the candidate installed at `/Applications/Chio.app`, retain these read-only checks:

  ```bash
  codesign --verify --deep --strict --verbose=2 /Applications/Chio.app
  codesign --display --entitlements :- /Applications/Chio.app
  spctl --assess --type execute --verbose=4 /Applications/Chio.app
  xcrun stapler validate /Applications/Chio.app
  ```

  Inspect each nested component's identity/entitlements separately; a successful deep verification does not replace its inventory. Submission credentials remain in the release owner's custody, never command output. After these candidate checks, publish the immutable candidate bytes for the controlled qualification harness; this availability carries no supported-runtime claim.

- [ ] Install the exact downloaded candidate on a clean standard-user Mac with normal SIP/Gatekeeper settings. Separately refuse every requested permission, registration and enrollment. Verify correct unavailable states and no request for unrelated ES/NE permissions. Test two users and offline ticket behavior.
- [ ] Run package-admission negatives for every candidate, including observation-only and approval-only without M6/M7. Start from the valid installed baseline above, change one tested dimension per fixture, and attempt the same installation/update path: tamper with one signed resource/helper without resigning; remove the required signature from otherwise identical content; supply an independently correctly signed wrong-architecture build from the same source so architecture rejection is not merely a signature failure. If that architecture can run via translation, it still must be rejected when absent from the qualified tuple; never silently use Rosetta. Independent before/after service registration, process and installed-generation inventories must show no activation or replacement by the rejected package; native approval-dispatch/effect counters remain unchanged. Preserve the already valid installation. Restore the valid package as a positive control. Put validator mutations in `PackageAdmissionTests.swift` and execute `swift test --package-path integrations/macos` after implementation; execute the clean-host cases in `package-admission-cases.md` through the actual shipped installer/update entrypoint recorded in M9. No negative is satisfied only by its own error log.
- [ ] On the same clean installed signed candidate, execute `finder-services-cases.md`: invoke Finder Services with one valid synthetic project in both app-cold and app-running states; observe only a proposal until authenticated owner intake succeeds and user confirmation follows the owner flow. Repeat with malformed/non-file/oversized pasteboard input, denied intake, unavailable owner, stale session, and a path/symlink replacement between handoff and intake. Independently verify no native resource capture, work creation, grant, approval dispatch or model release for rejected/pending proposals. The valid control must complete handoff without executing a filename or reading ambient data. With intake unavailable in an observation-only build, show the reason and keep the proposal non-authorizing. These signed handoff results complete M2 acceptance and gate M10.
- [ ] Interrupt update before/after native fencing, file replacement, migration and service reactivation; hold an old active component and deny replacement. Roll back app bytes and restore old app-state fixtures. Confirm native authority does not rewind or replay spent grants. Uninstall while work is unresolved; report retained custody and remove only selected application-owned artifacts.
- [ ] For each included credential-custody path, qualify rollback independently of W1/M6/M7 in a dedicated synthetic test-user account: snapshot both app state and the per-user Keychain/credential-owner fixture before a grant is spent or revoked; exercise spend and revocation in separate trials while preserving the newer native authority outside the restored snapshot. Restore app state and Keychain together, then separately only one of them, and remove all required freshness access. Re-submit the restored credential against the original and a new operation. Newer authority or unavailable freshness must fence every stale attempt: independent approval dispatch/effect counts cannot increase, the spent/revoked credential is not retained as newly valid, and the UI reports unavailable reconciliation. A current unspent credential with live freshness is the positive control. Restore no real user Keychain. Record which credential store, generations, freshness routes and synthetic item bytes were rolled back; Keychain storage alone is not an anti-rollback witness. An observation-only build with no mutating credential-custody path must prove that absence and that restoring planted synthetic stale items cannot enable a mutation; it does not acquire an M3 prerequisite just to run this package check.
- [ ] Execute every annex performance workload and threshold applicable to the delivered profiles with the specified sample counts. Record owner-approved exclusions for unimplemented execution/VM/provider surfaces explicitly; common UI/IPC/privacy limits are mandatory even for observation-only builds, and excluded features remain unavailable. Distinguish local overhead from provider/network time, fence from termination and external completion, Mac shell from browser/VM/provider resource cost. High-load failure, energy-resolution insufficiency and safety failure are explicit results, never omitted samples.
- [ ] Independently recheck candidate report hashes and tuple bindings, then hand the immutable signed bytes and distribution/performance results to M7 for final I08 and to M10 for evidence joining. Review and commit only generated candidate evidence. Keep unqualified profiles disabled outside the controlled harness; any byte or profile-configuration change requires a new candidate identity and affected qualification.

**Acceptance:** Candidate assembly/signing/notarization and controlled publication can complete before M7. Clean installation, denied permissions, update interruption, restoration, removal and performance evidence bind the same candidate; M7 supplies final host qualification and M10 joins all required evidence before release promotion. Local build, notarization, deployment and enforcement remain separate evidence columns.

### M10: Join qualification evidence and promote exact passing profiles

**Fields:** `boundary_class: advisory_only` for release evidence review; `prevent` at native profile admission; `planning_status: ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** M9 immutable signed candidate and distribution evidence; M8 privacy/lifecycle evidence for every delivered profile, with only unimplemented artifact-specific cases excluded; M1-M6 evidence required by each selected profile; completed M7 applicable I01-I08 for each included host, including sealed-work hosts, with explicit doc 19 owner dispositions for any inapplicable subcase and I08 required for each shipped integration. Enterprise evidence from M11 is required only for an explicitly included managed-endpoint profile. This packet is not a prerequisite for M9 candidate construction or M7 qualification.

**Files:** Review the shared qualification envelope and M9 component inventory/release checks. Modify the existing shared release/profile admission configuration at the owner location recorded in M0, without creating a Mac authority schema.

**Interfaces:** Consume candidate-bound evidence and native profile admission. Produce the exact supported-profile allowlist and release decision, leaving every other row unavailable.

- [ ] Join the candidate source, final signed bytes, installed/active component generations, OS/CPU/runtime identities and profile configuration across all required evidence. Reject stale, skipped, mismatched or missing artifacts.
- [ ] Require useful work and independent negative-effect probes for each selected profile, M7 applicable I01-I08 for each included sealed or interactive host, M2 signed Finder handoff evidence, and M8/M9 privacy, lifecycle, invalid-package rejection, credential rollback, distribution and performance closure. Candidate signing or publication alone cannot satisfy any of these gates.
- [ ] Derive the proposed release allowlist solely from passing exact cells. Verify every unqualified or deferred profile stays disabled outside the controlled harness, including retired `native-descendant-v1`.
- [ ] Check whether enabling the allowlist changes any signed bytes, effective profile configuration or authority generation bound by qualification. If it does, issue a new candidate identity and rerun the affected checks before promotion; never reuse evidence across an unreviewed activation delta.
- [ ] Independently verify that ordinary startup admits only the reviewed passing cells and reports every other row unavailable. Repeat one allowed useful operation and one forbidden-effect probe on the promoted tuple.
- [ ] Review/commit the generated release decision and publish only its exact supported claims. Keep candidate availability, release promotion and production behavior as separate reported facts.

**Acceptance:** Release promotion follows completed candidate qualification without a dependency cycle. No ordinary profile is enabled merely because its code was bundled or its candidate was signed/notarized.

### M11: Keep managed endpoint work independently gated

**Fields:** `boundary_class: detect_only` for sensor evidence and `cannot_see` for unmediated local effects; `planning_status: deferred`; `runtime_evidence: unavailable`.

**Depends on:** a separately opened managed-endpoint implementation decision, actual team entitlement/provisioning access, final SDK/OS support and scoped administrator policy. Not a prerequisite for ordinary desktop observation or sealed work.

**Files:** Read the retained [Apple](../../specs/2026-10-07-macos-integration/research/apple-platform.md), [distribution](../../specs/2026-10-07-macos-integration/research/distribution.md) and [Clawdstrike](../../specs/2026-10-07-macos-integration/research/clawdstrike.md) research. Any new provider source location is chosen in that independently approved work packet, not presumed to exist here.

**Interfaces:** Consume native restriction requests and emit externally sourced evidence with provenance. No new approval issuer, Chio grant, task identity, or atomic cross-product stop promise.

- [ ] Obtain entitlement/provisioning eligibility and exact provider-type deployment rules before provider construction; missing eligibility leaves this track unavailable.
- [ ] Revalidate candidate Clawdstrike blobs and reuse only named event conversion, callback, filter and evidence-gate seams. Preserve the default-allow observer and PID-incarnation limits from the source review in all claims.
- [ ] Test signed activation/removal under administrator and standard-user conditions, MDM configuration where selected, two users, coexisting providers and explicitly refused permissions.
- [ ] Require actual file/flow denial and restoration, wrong/missing audit-token attribution, inherited/open handles/flows, callback deadline/queue overflow, crash/disconnect and policy-generation convergence with independent oracles.
- [ ] If descendant APIs are researched, pin final SDK headers and observed OS behavior; do not reopen `native-descendant-v1` or infer Seatbelt substitutes for ES/NE coverage. A future new profile needs its own decision and qualification.
- [ ] Review the independent enterprise report and its precise claims before enabling that profile. Until then this packet remains deferred and every enterprise runtime result unavailable.

**Acceptance:** Enterprise restrictions are useful only at their proved OS control points and remain separate from the desktop grant path. No ordinary Mac profile depends on host-wide provider activation.

## Execution exit checks

- [ ] Every annex section maps to M0-M11; every active packet has a recorded source revision, owner contract, actual failing/passing tests and independent installed acceptance appropriate to its claim.
- [ ] The five Review Focus inputs have cases in their named packets, including original-operation recovery for unknown effects.
- [ ] The Mac client uses only the shared projection; task/recovery/events/identity/stop/credential contracts remain at their owners.
- [ ] Shared `planning_status` is not interpreted as runtime availability. All unexecuted, skipped, stale, incompatible or wrong-architecture cells remain unavailable.
- [ ] The retired profile and superseded operator protocol names are rejected by configuration/migration rather than silently mapped to a weaker backend.
- [ ] Final public copy contains only supported exact-tuple claims and public Chio links. Source evidence, local tests, signed installation and release/production behavior are reported separately.
