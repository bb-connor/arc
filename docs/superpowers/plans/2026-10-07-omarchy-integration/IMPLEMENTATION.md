# Omarchy Desktop Operator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the Omarchy platform client and packaging for the shared desktop operator, with browser-first observation and a first sealed W1 work experience, then qualify the exact publicly retrievable installation.

**Architecture:** One C-layer `chio-operator` controller outside the TCB serves the workbench and thin platform clients through proposed `chio.operator.v1`. Linux reuses `chio-secure-ipc`, `chio-process`, the secret broker/model relay, Pi restricted execution and Docker-based `chio-mini-swe`, with rootless Docker as its first unqualified engine candidate. Kernel/work/recovery owners retain every authority-bearing concept. Omarchy contributes QML, user-session integration, opt-in launchers and pacman delivery.

**Tech Stack:** Rust shared controller/client, existing browser workbench, Omarchy QML/Quickshell, Linux peer credentials and systemd user units, existing bubblewrap/container adapters, Arch devtools/pacman, existing owner tests plus bounded shared qualification tooling.

Status: dependency-gated implementation plan under accepted [ADR-0038](../../../adr/ADR-0038-desktop-operator-program.md). No packet has been executed by this document. Confidence: high in ownership and dependency ordering; moderate in platform feasibility; unknown in installed runtime qualification. Checkboxes are deliberately open.

Read [the annex](../../specs/2026-10-07-omarchy-integration/ANNEX.md), [shared program](../../specs/2026-10-07-desktop-integration/README.md), [qualification](../../specs/2026-10-07-desktop-integration/QUALIFICATION.md), [operator protocol](../../specs/2026-10-07-desktop-integration/OPERATOR.md), [program map](../../../architecture/PROGRAM-MAP.md) and retained [research](../../specs/2026-10-07-omarchy-integration/research/omarchy-upstream.md) before implementation.

## Execution rules and dependencies

`planning_status` uses ADR-0011's existing vocabulary. `ready_after_adr` records the accepted design; each packet's `execution_gate` states what must actually be delivered. A predecessor may be planned as shipped while its source/API is still absent from this branch. In that case record the missing owner artifact, stop only the dependent step, and continue independent platform/documentation work. Never create a stub that reports native success.

All paths below are **planned** unless confirmed by packet O0. `crates/products/chio-operator` and `tests/integration/operator` are shared-program paths. Platform code lives under `integrations/omarchy`, `packaging/omarchy` and `tests/integration/omarchy`. Owner modules such as `chio-secure-ipc`, `chio-process`, W1, recovery, S7 and the workbench must be located from the integrated source map before editing. Do not create an Omarchy copy when a predecessor is unavailable. Any listed command referring to new files is a future verification command, not a command asserted to work today.

| Packet | Depends on | Output |
| --- | --- | --- |
| O0: freeze sources and owner handoff | Accepted shared decision | Exact source/API/acceptance map and platform baseline. |
| O1: Linux controller deployment | O0; shared transport/controller; Linux peer-auth owner | One tested user service and navigation-only client. |
| O2: observe and thin QML | O1; workbench; S5 Part B and recovery-safe projections | Honest observed sessions and a native shell entry. |
| O3: sealed W1 work | O1/O2; W1, recovery fixes, S3/S4/S7/S8/S9/S10 owner gates | Existing runner/resource composition connected to workbench. |
| O4: exact approval and stop UX | O2 and the selected action's S4/process, S8 or S28/verifier/installed-utility gates | Attributable owner decisions and accurately scoped stops, independently of sealed-work release. |
| O5: protected default-agent entry | O1/O2 and owner adapter implementation for candidate assembly; O6 installed candidate for I01-I08; first sealed W1 release and later protected O7 promotion for production activation | Disabled unqualified entry first; production launcher follows sealed release and its own installed-host/release gates. |
| O6: packages and public candidates | O1/O2 deliverables and implemented components from O3/O4/O5 for selected candidates; final I08/release acceptance is not a publication prerequisite | Signed unqualified packages and disabled-install Git plugin candidate. |
| O7: independent Omarchy qualification | O6 public candidate and selected-profile owner gates; sealed promotion consumes O3 without O5; later protected promotion additionally consumes O5 I01-I08 and the first sealed-release record | Independent clean-host evidence; sealed execution release before protected execution release. Observe/approval/stop promote independently. |

Candidate build prerequisites and production activation gates are distinct. O5 may assemble and test a disabled protected candidate from O1/O2; O6 publishes its exact unqualified bytes before final installed-host I08 acceptance. Independently, O3 supplies sealed W1 composition, O6 publishes its candidate, and O7 qualifies that installed tuple and promotes the first sealed W1 release without waiting for O5. Protected production activation and a later protected O7 promotion require that recorded sealed release plus O5's exact installed I01-I08 and all protected-profile gates. Passing protected-host tests cannot substitute for sealed-release evidence. O6 can package implemented execution components while final installation qualification is open, with affected product controls disabled. Qualification exercises use the owning test harness on the explicitly selected test host and confer no production-ready label or authority bypass. O7 cannot turn an unavailable execution profile into a pass by excluding its negative cases. Observe, approval and stop qualify and promote independently under their own native gates; publication retains its separately scoped prerequisites. Boundary interactive remains deferred; compositor tools/configuration repair are removed; delegated work stays with kernel/work/process owners.

## Packet O0: Freeze predecessor and platform evidence

`boundary_class: advisory_only`  
`planning_status: ready_after_adr`  
`execution_gate: accepted ADR-0038 and access to the exact predecessor sources; runtime implementation waits for each named owner gate.`

**Files:** Create `integrations/omarchy/README.md`, `integrations/omarchy/compatibility/README.md` and `integrations/omarchy/compatibility/source-map.md`. Reuse the shared qualification evidence format for measured tuples. Amend retained research only for newly inspected evidence; do not add a parallel requirement catalog or JSON example corpus.

- [ ] Locate the integrated owner surfaces using the program map and source inventory. Record revision, concrete file/API, native test entrypoint and retained acceptance for W1/work views, recovery, S3, S4, S5 Part B, S7, S8, S28, S9 M20, applicable S10, secure IPC, process custody, broker/relay, `chio-mini-swe`, Pi and workbench. Distinguish missing source from present-but-unqualified source. A missing owner is a dependency, not permission to implement its protocol here. S11 is conditional on a later injection-safety claim, not a first-product prerequisite.
- [ ] Reconcile the S8 phases exactly: phase 1 supplies durable `Kernel` stop and S30 routes/results; S28 production operator roster is phase 3; `Tenant` and `Recovery` emergency scopes wait for phases 4 and 5. Per-task closure is S4 phases 1 and 2. Keep those acceptance artifacts separate.
- [ ] Pin Omarchy v4.0.4 and the observed development revision independently. On an owned x86_64 Omarchy host record actual Qt, Quickshell, Hyprland, kernel, systemd, bubblewrap, container engine, LSM/cgroup/user-namespace state, session target and unit overrides. Source package lists and the architecture review are not installed-system measurements.
- [ ] Record the engine privilege tuple: exact runner/CLI/API/daemon/container-runtime/helper identities, rootless or rootful daemon mode, host UID/GID/groups, socket identity/permissions, effective client/daemon config and units, user-namespace UID/GID maps/subordinate ranges, image/storage/network drivers and cgroup delegation/limits. Inspect the actual mini-swe engine calls before selecting a backend. Pinned Omarchy enables the system Docker socket but does not grant docker-group membership by default; record existing host posture without inferring it from package presence. Rootless Docker is the default candidate; existing mini-swe evidence does not qualify it.
- [ ] Map storage/output enforcement and admission to the existing runner/resource owners: actual writable volume/layer/temp/cache locations and inode domains, stdout/stderr ingress/buffers/retention, and every host engine-log/journal/spool sink outside the container. Record concrete native APIs and test entrypoints for finite per-task and aggregate quotas, concurrent admission reservations and receipt/controller/stop headroom. Select numeric bounds from measured owner/platform constraints before O3 admission; missing enforcement remains an owner dependency, not an invented Docker flag, desktop quota service or monitoring-only limit.
- [ ] Record the six mandatory doc 19 hosts and the exact current I01-I08 state of each. Pi's historical 0.1.0/0.85.1 record is evidence to inspect, not a pass for current Pi/Node/runtime/package pins. Label hook-mode sessions `detect_only`; unattended upstream agent flags are not a protected launch profile.
- [ ] Build the dependency record from owner-provided artifacts, with independent source/public-package availability fields. Use the shared evidence verifier only after it exists; document its real command. Do not invent a native compatibility API or a gateway endpoint to make this step executable.
- [ ] Build the complete selected-surface case map required by shared QUALIFICATION: every consumed OPERATOR normative obligation and freeze-acceptance row, each shared Q stimulus and each annex requirement has a native owner, implementation packet, actual test command, positive control and independent negative result. Include raw decoding, initial/reconnect negotiation, paginated owner mutation/snapshot expiry, colliding-owner review invalidation and adversarial hook/receipt association. A delivered read-only budget view adds Q15 projection/rendering cases without acquiring execution enforcement prerequisites. Missing cases remain explicit blockers; O7 must remove each case individually from an otherwise passing candidate manifest and verify affected activation/promotion refuses. Unexposed optional surfaces remain unavailable rather than claiming their acceptance.

Source discovery commands, valid against a checked-out tree, include:

```bash
rg --files crates integrations tests docs spec | rg 'chio-(secure-ipc|process|mini-swe)|workbench|OPERATOR|priority-agent|recovery'
rg -n 'WorkHandleV1|WorkViewV1|InspectWorkflow|SubmitApproval|ResumeWorkflow|CancelWorkflow|PasskeyCapabilityVerifier' crates integrations spec
git ls-remote --symref https://github.com/omacom/omarchy.git HEAD refs/tags/v4.0.4
pacman -Q
uname -m
uname -r
systemctl --user status graphical-session.target
```

Resolve the reported symbolic HEAD and tag object/peeled commit before locking. Capture only relevant package/session facts in the redacted release evidence.

**Acceptance:** A reviewer can trace every proposed owner call to its actual source and test, and every platform claim to an installed observation or an explicitly unexecuted gate. An absent predecessor produces a named blocker. No runtime pass, current download claim or public checkout instruction uses a private-only revision.

## Packet O1: Deploy the shared controller on Linux

`boundary_class: prevent` for authenticated owner command routing; `advisory_only` for diagnostics/navigation.  
`planning_status: ready_after_adr`  
`execution_gate: shared controller and proposed operator ABI implemented after S5 Part B; qualified chio-secure-ipc Linux path and native owner connectors.`

**Files:** Shared-owner edits in `crates/products/chio-operator` and `tests/integration/operator`; create `integrations/omarchy/client/`, `integrations/omarchy/launcher/`, `packaging/omarchy/units/chio-operator.service`, `tests/integration/omarchy/test_session_lifecycle.py` and `tests/integration/omarchy/test_operator_transport.py`. Establish these paths in the owner handoff before adding modules; a client shim can reuse the shared CLI binary if that is the delivered design.

- [ ] Write failing shared/real-Linux tests for wrong UID, stale socket, unavailable native endpoint, protocol mismatch, guest attempts to reach the operator socket and a disconnected client with an unresolved command. Use `chio-secure-ipc` authentication; transport modes and JSON fields cannot assert peer identity.
- [ ] Wire one shared controller process, outside the gateway/process-host address spaces. Reuse common codecs, snapshot/resubscription and the selected Observe adapters; add work/recovery connectors and native retry classifications only for independently qualified functions. Prove read-only reconnect cannot dispatch work. For included commands, prove disconnect/reconnect performs original-command lookup and cannot change authority bindings or replay a mutation under a fresh identity.
- [ ] Build a fixed-view opener and, only if QML requires it, a bounded client shim. Literal package-owned argv, private stdin/FD payload, minimal environment, bounded output and common transport limits are required. Reject arbitrary commands, URLs and file paths in navigation. Add canaries for prompt/credential leakage through argv, environment, process titles and journals.
- [ ] Add an inert user unit for the shared controller. Onboarding activates it explicitly. Start with role-appropriate restrictive umask, bounded restart/stop, core suppression and fixed executable paths; evaluate hardening directives on the actual user manager. Do not enable linger, create a root service or couple task lifetime to QML destruction.
- [ ] Implement the annex's initial single-enrolled-session policy through the shared IPC/session owner. Persist only the native session binding needed for reconciliation: UID, boot/logind session identity and controller incarnation; derive caller association from authenticated peer/native enrollment facts, never `XDG_SESSION_ID`, environment fields, UID equality or socket possession alone. Refuse incomplete identity and a second concurrent graphical session for the same UID. On logout/lock or lost liveness, fence affected reads/actions and request closure only for original owner references bound to that session; never issue a user-wide or Kernel stop as an implicit logout action. A lingering user manager, controller restart or another session's activity cannot rebind the instance. A new session requires explicit enrollment after reconciling original custody.
- [ ] In real Linux session tests, run two graphical sessions A/B for the same UID with distinct native enrollment and outside effect sentinels. A is the valid control; B's enrollment, spoofed session environment and copied client references must disclose no protected A data and dispatch no A action. Lock/logout A while B remains active, repeat with pre-existing linger and dropped logind notifications, restart the controller, and attempt takeover from B while owner reconciliation is absent/delayed. A's original custody stays visible only to authorized reconciliation; B's unrelated work/services remain unchanged and no automatic reassignment or global stop occurs. Test explicit re-enrollment only after the owner permits it. Retain independently observed logind/process identities, native scope/dispatch records and both sessions' sentinels; a headless single-session fixture cannot qualify this gate.
- [ ] Exercise login/logout with and without pre-existing linger, lock/unknown-lock, suspend/resume, missed logind events and controller crash. `chio-process` remains custodian. Session loss stops new admission and invokes qualified closure/termination policy; process restart recovers views without automatically running agents.
- [ ] Retain a per-role effective-protection table for controller, launcher, relay, guest and resource. Verify required namespaces/cgroup controllers and Node thread behavior; missing protection refuses rather than falling back to an unrestricted process. No analyzer score substitutes for kernel/negative observations.

Future checks after implementation:

```bash
cargo test -p chio-operator
python3 -m unittest discover -s tests/integration/omarchy -p test_operator_transport.py -v
python3 -m unittest discover -s tests/integration/omarchy -p test_session_lifecycle.py -v
systemd-analyze --user verify packaging/omarchy/units/chio-operator.service
```

The Python cases must report an unavailable real host distinctly from pass. Unit-file syntax checking is not systemd lifecycle acceptance. Verify package/proposed binary names against the implemented shared controller before publishing these commands.

**Acceptance:** Exactly one controller and authenticated native connection path. A hostile guest/wrong peer cannot issue operator commands. QML exit does not kill admitted work; desktop session loss follows the selected owner policy even under linger. Unknown effects remain recoverable through their original identity.

## Packet O2: Deliver browser-first observation and the thin QML shell

`boundary_class: detect_only` for hook observation; `advisory_only` for shell navigation.  
`planning_status: ready_after_adr`  
`execution_gate: O1, workbench Observe client, S5 Part B and shared packet 2a read/source-attribution adapters. W1 task and recovery views require their separately selected owner bindings; they are not prerequisites for basic receipt/hook observation.`

**Files:** Workbench owner files located by O0; create `integrations/omarchy/plugin/{manifest.json,Service.qml,BarWidget.qml,Panel.qml}`, `integrations/omarchy/plugin/components/`, `integrations/omarchy/desktop/computer.chio.desktop.desktop`, `tests/integration/omarchy/test_shell_lifecycle.py`, `tests/integration/omarchy/test_ui_privacy.py` and rendered acceptance notes under `integrations/omarchy/acceptance/`.

- [ ] Connect the workbench to shared trust-control read and hook-source projections first; preserve their native read authority. Display receipt kind, current boundary class, host provenance and missing evidence. Test that hook disappearance/crash leaves the session `detect_only` with a gap and never converts observation into authorization. Basic Observe passes its shared Q04, Q09-Q11, Q16-Q17 and Q21 cases without W1/M20. If W1/recovery views are included, separately qualify their owners and Q01-Q03 cases and display all six `WorkViewV1` observations independently; missing optional views stay unavailable.
- [ ] Write failing common-client tests for missed events, old epochs, duplicate hints, slow consumers and disconnected operation replies. Implement S5 resynchronization through the owner transport. Assert there is no timer polling `InspectWorkflow` for UI refresh and no per-widget subscription storm.
- [ ] Add the minimal manifest with `bar-widget`, `panel`, `service` and `keepLoaded: false`, using only inspected upstream fields. QML starts one client after property injection; generation checks discard obsolete callbacks. The panel handles bounded navigation-only opens and delegates full task/editor/review flows to the workbench.
- [ ] Run late injection, repeated ready callbacks, 20 widget instances, panel open queues, shell reload during an unknown reply, plugin disable and unsupported replacement bar cases. Process/native-effect counters must remain stable. Destruction closes only presentation transport and sends no cancel/approval/resume request.
- [ ] Use theme roles with release-compatible feature probes. Add Accessible metadata, text/shape statuses, keyboard focus, large text and reduced motion. Verify actual IME/editor input without `PanelKeyCatcher` stealing keys. Record rendered runs on the selected baseline(s), not a headless import alone.
- [ ] Clear sensitive detail on lock and unknown lock. Test persisted notifications with `app_name=Chio`, normal urgency, DND and a fixed opener action. Seed canaries in source, prompts, paths and tokens; scan notifications/history/logs/diagnostic export. Opening an old notification refreshes state and cannot grant, retry or publish.
- [ ] Validate plugin-only loading with no backend. Show exact unavailable dependency/version information without download, pacman, polkit, service installation, credential import or task launch. Keep only visual preferences in Omarchy settings.

Future checks:

```bash
omarchy plugin validate integrations/omarchy/plugin
python3 -m unittest discover -s tests/integration/omarchy -p test_shell_lifecycle.py -v
python3 -m unittest discover -s tests/integration/omarchy -p test_ui_privacy.py -v
```

Run the workbench's actual unit/browser test commands recorded in O0, including live navigation from desktop entry/Walker. Do not invent its package manager or test scripts before inspecting it.

**Acceptance:** The first usable operator client is the workbench. QML adds native status and navigation without a second editor/task runtime. Screen reader/keyboard/IME/privacy and real multi-monitor behavior are recorded; unsupported combinations remain unavailable. Observe mode makes no protected-execution claim.

## Packet O3: Connect sealed W1 work through existing runners

`boundary_class: prevent` at qualified kernel-owned tools and egress; `cannot_see` for any undeclared internal activity.  
`planning_status: ready_after_adr`  
`execution_gate: O1/O2; W1, recovery P1 fixes, S3 phase 1, S4 phases 1/2, S7 backend kind, S8 phase 1, S9 M20 and applicable S10 acceptance; current Pi host/resource/provider qualification.`

**Files:** Extend the owner-located `chio-mini-swe`, Pi restricted-session/coding-resource and workbench modules; shared integration tests under `tests/integration/operator`; create only the platform case adapter `tests/integration/omarchy/test_sealed_work.py` and measured backend setup notes under `integrations/omarchy/compatibility/`. Do not create a desktop task enum, runner, resource ledger, sandbox library or model proxy.

- [ ] Map one single-owner unpaid W1 work commitment to the existing runner/workbench flow: explicit request, enrolled project, fixed recipe, scoped tools, expected acceptance and review artifact. Identify source intake and dirty-tree handling in the workbench/resource owners. Extend those owners to preserve originals where necessary; avoid an Omarchy-specific importer.
- [ ] Before restricted launch, qualify the existing resource owner's repository capture against hostile Git configuration/attributes, filters/text conversions, fsmonitor/hooks, submodule/helpers, promisor/lazy fetching, replacement refs, alternates and external object stores. Disable/reject repository-controlled execution, network and outside-object access using the owner's actual capture API; record its commands rather than assuming a safe archive command. Independent process/file/network observers must be active before import and prove no unauthorized host reads, helper execution or egress, with rejected capture producing no model/runner dispatch and any retained preparation/work record staying non-executable. Include source/config/path replacement and restart, and a self-contained repository whose exact immutable bytes capture successfully. Apply shared atomic duplicate work-create cases at native lookup/admission/commit: one work/effect for exact duplicates and conflict before dispatch for a same-ID changed intent. Record owner-native regressions and installed results; later container confinement cannot qualify pre-launch capture.
- [ ] Adapt the existing `chio-mini-swe` networkless Docker workspace and mediated `sandbox/execute` path to the exact rootless Docker candidate, plus Pi's restricted bubblewrap session where required. First demonstrate the runner's CLI/API, image, copy/archive, exec/stream/exit, bind-mount ownership and stop/remove behavior; fix gaps in that owner. Bind the measured local endpoint and effective config independently of ambient contexts/environment. Rootless Podman requires a separate compatibility evaluation of those actual calls and its custody semantics before selection, with separate acceptance; do not replace `docker` with a Podman alias and assume equivalence.
- [ ] Keep engine access in the trusted host-side runner. Deny sockets, API credentials, inherited connected FDs and docker-group privilege to guests and recipes; inspect effective group credentials and probe all known engine endpoints from outside and inside the guest. A rootful Docker-group profile is a separate explicit opt-in with documented root-equivalent runner/daemon trust and its own full qualification. Installation never grants group access, changes upstream workloads or chooses rootful as recovery from a rootless failure. Chio authority remains with the existing native owners.
- [ ] Bind exact images, Node/libraries, mounts, descriptors, policies and recipe to the O0 engine privilege tuple. Verify `AgentHostBwrap`/`ProcessContainer` with S7; unknown evidence is unavailable. Observe actual daemon credentials and user namespaces independently of engine self-report. Missing or changed namespace mapping, socket/config identity or rootless capability refuses before dispatch and cannot trigger sudo/rootful fallback.
- [ ] Measure effective cgroup v2 delegation and the selected CPU, memory and PID limits on the container's actual host cgroup. Exercise bounded resource pressure and compare independent counters/limits with requested values, then prove cleanup under pressure. Accepted CLI flags alone do not prove enforcement. Missing required delegation/limits leaves the profile unavailable; it cannot be repaired by silently weakening limits or switching engines.
- [ ] Before admitting a task, enforce O0's finite per-task and aggregate writable-byte/inode quotas over volumes, writable layers, temporary/cache storage and host engine metadata, plus stdout/stderr ingress, buffer and retained-output limits and engine-log retention. Include Docker logs, journals and spool files outside the container's mounts. The native owner reserves shared capacity under concurrent admission while retaining measured capacity for receipts, original-operation state, the controller and stop/recovery. Independently inspect actual host quota/usage and output/log sink bounds; a read-only root, accepted quota flag, client output cutoff or disk-free precheck cannot alone establish this gate. Missing, ineffective or drifted bounds refuse admission.
- [ ] Run positive work beside silent byte/inode exhaustion and output overload: write volumes/layers/temp/cache without producing output; flood stdout and stderr separately and together; stall/disconnect their consumer; and repeat with concurrent tasks and host engine-log growth. Independent host filesystem/quota, sink-size and ingress/buffer measurements must show per-task and aggregate limits hold before receipt/controller/stop headroom is consumed. Verify admission refusal, responsive stop and bounded cleanup under pressure; lost results or unresolved storage/process cleanup retain their owner uncertainty/custody and cannot report successful acceptance. Never prune authoritative receipts or original-operation fences to free the reserve.
- [ ] Route provider credentials through the existing broker/model relay and kernel-owned tools through the actual native gateway. Implement private task input in the owner launcher/SDK if current CLI argv exposes prompts. Required governance refuses when its native facade is absent; it never downgrades to execution-only. Show enforceable and unavailable provider-limit dimensions truthfully.
- [ ] Add a positive actual-kernel task covering source read, bounded edit, fixed test, native receipts/history/delivery behavior and SHA-256 review artifact. A recipe pass must leave acceptance/result/delivery as separate owner observations. Checkout publication is absent until its separately qualified path is enabled.
- [ ] Apply the shared packet 5 evaluator boundary explicitly: any separate acceptance import/build/test runs through the existing qualified runner with captured input and pinned dependencies, not the workbench's ambient host `Command` path. Trusted result validation and W1 commit stay outside candidate execution. In the runner/work owner's actual suites, use a known-good artifact and malicious evaluator-triggering candidates that attempt host/credential reads, outside writes, IPv4/IPv6/DNS/loopback egress, inherited handles, unrelated process signals, descendant escape, forged result-channel input and silent resource exhaustion. Independently prove no forbidden effect, bounded cleanup and no accepted result for failed/unknown evaluation; bind separate S7/process evidence to the evaluator tuple. Existing recipe pressure/escape tests qualify only that recipe boundary. Missing evaluator isolation disables sealed acceptance without disabling Observe.
- [ ] Extend owning Linux tests for forbidden filesystem and raw network access, alternate syscalls, inherited sockets/FDs, `/proc`, namespace changes, hardlinks/symlinks, child creation and recipe escape. Do not use the strict `chio-cage` profile for Node or relax it. Test exact x86_64 native Omarchy; ARM64 privileged-container history remains separate.
- [ ] Verify process custody using the shared Linux harness: double-fork, detached/process-group escaping descendants, full pipes, timeout and stop escalation. A dedicated fixture worker establishes/verifies subreaper custody before launch and reaps within a bounded deadline. Failure to initialize refuses the case; unresolved cleanup fails it and retains custody evidence. Reconcile engine-owned containers across runner/daemon crashes using the existing process/backend owner, with host cgroup/process census as the absence oracle; CLI or runner exit does not establish container termination. Do not add an Omarchy-private subprocess runner or alter the controller's subreaper state.
- [ ] Inject lost reply after an independently counted resource effect, gateway/process-host/engine-daemon crash, trusted runner and controller restart and late host history delivery. Use W1/recovery originals and S9 classes to recover. A new task ID, reopened panel or new conversation cannot clear uncertainty. Assert no repeated external effect with an independent mutation counter.
- [ ] Test task closure during recipe execution and a previously admitted effect. Render S4 result kinds and verify descendant absence separately from remote effect outcome. Preserve unresolved records and receipt anchors across reload/stop/restart.

Future platform check:

```bash
python3 -m unittest discover -s tests/integration/omarchy -p test_sealed_work.py -v
```

Execute the exact mini-swe, Pi, workbench, process, S7 and recovery test commands from their pinned owner handoffs. Both positive work and outside-guest negative controls must run. A mocked owner reply closes only a component test.

**Acceptance:** One reviewable W1 task executes through reused owners on the actual selected Omarchy tuple. The workbench displays genuine owner evidence, original recovery prevents duplicate effects, and S7/process observations plus host credentials/namespaces/cgroup/quota/output measurements independently establish the exact engine privilege, isolation, custody and resource claims. Storage/output overload and concurrent admission preserve receipt/controller/stop headroom. Rootless mini-swe compatibility must be demonstrated; a separate opt-in rootful result does not qualify it. All omitted/unexecuted native/provider tests remain explicit blockers. O3 composition evidence proceeds through O6 candidate delivery and O7 installed qualification/promotion before it supplies the first sealed W1 release prerequisite for protected activation.

## Packet O4: Expose attributable approval and accurate stop controls

`boundary_class: prevent`  
`planning_status: ready_after_adr`  
`execution_gate: O2 plus the selected action's owner gates: per-task stop requires S4 phases 1/2, Kernel stop requires S8 phase 1/S30, approvals require S28 phase 3, production passkey verification and repaired installed Pi bridge utility; reviewed publication requires O3 plus owner publication acceptance.`

**Files:** Shared controller/workbench connectors and existing approval/bridge owner tests; platform UI amendments under `integrations/omarchy/plugin/`; create `tests/integration/omarchy/test_approval_stop.py`. No QML signer, desktop approval token type or substitute authority file.

- [ ] Track the existing Pi utility defect with its native bridge owner. Confirm whether a fix exists before changing dependency pins. The wrapper's refusal is useful mitigation but does not repair the directly callable bundled `chio-gateway-operator` binary.
- [ ] Run the installed replacement utility directly: requested denial receiving an approved credential, wrong approval ID, wrong request digest/subject/authority/expiry, replay and stale original. Every negative must retain no credential and dispatch no effect. Inspect credential storage and an external effect counter; wrapper-only tests are insufficient.
- [ ] Connect the production S28 identity and passkey-verification path. Test unknown/revoked operator, missing roster, shared sidecar credential, expired or mismatched challenge and absent production verifier. Unsupported identity renders `SharedCredential` or unavailable as supplied by the owner; UI authentication alone cannot claim approver attribution.
- [ ] Render exact owner approval/review bindings, including operation, project/resource, arguments or digest, recipient/destination and validity window. Lock, stale projection, changed artifact/destination or unknown result disables the action until owner revalidation. Approval acceptance is never synthesized by a local click or notification.
- [ ] Test deny, allow, stale/duplicate response and lost response with original-operation lookup. Keep authorization, effect completion and acceptance separate. Verify publication changes only the intended owner-bound artifact/destination; preserve unrelated dirty checkout work and require the owner writeback/review policy.
- [ ] Wire per-task Stop to S4 closure and broad emergency action only to implemented S8 scopes. Phase 1 permits `Kernel`; `Tenant` and `Recovery` wait for phases 4 and 5. Label scope explicitly and render S30 result kinds. A returned stop receipt does not prove that a previously admitted external effect was undone.

Future check:

```bash
python3 -m unittest discover -s tests/integration/omarchy -p test_approval_stop.py -v
```

Run the exact native suites required by each selected action's separate shared qualification row. Approval/bridge/S28 tests gate approvals, S4/process tests gate per-task closure, and S8 tests gate Kernel stop. A stop-only release may omit native approval controls while leaving their unavailable state explicit; missing approval results cannot block a separately qualified stop. No release may enable approval/publication without the installed utility negative gates.

**Acceptance:** Every enabled approval is attributable through qualified native identity and exact binding checks; direct installed utility negatives retain no credential/effect. Per-task closure and durable emergency scope are visibly and behaviorally distinct.

## Packet O5: Add the opt-in protected default-agent launcher

`boundary_class: prevent` for admitted protected tools; `advisory_only` for launcher selection.  
`planning_status: ready_after_adr`  
`execution_gate: candidate assembly/testing requires O1/O2 and implemented owner adapter contracts; production protected-entry activation requires the first sealed W1 release (O3 composition, O6 candidate and O7 installed qualification/promotion), I01-I08 against the exact O6 installed protected candidate, and its later O7 promotion. Pi first does not waive other hosts' gates.`

**Files:** `integrations/omarchy/launcher/`, package-owned desktop/menu fragments in `integrations/omarchy/desktop/`, `tests/integration/omarchy/test_host_launcher.py`; extend each host adapter at its owner path when required.

- [ ] Add **Launch default agent in protected mode** as a distinct desktop/Walker or owned menu action, initially disabled and labeled unqualified in the candidate. Inspect the selected upstream default through a tested adapter and display the resolved host. Do not rewrite `omarchy-agent`, aliases, shortcuts or upstream package files, and do not shadow `pi`. Its build and O6 publication do not wait for final I08 acceptance.
- [ ] Keep a host-generic selection boundary for Claude Code, Codex, Cursor, Hermes, Pi and OpenClaw. Resolve only a locked, individually qualified adapter tuple. Unsupported/missing/drifted hosts refuse with a clear reason and permit an explicit alternative selection; there is no fallback to upstream auto-approved launch.
- [ ] Verify protected mode removes native shell/direct execution routes, uses qualified gateway file/tools and denies bypass. Hook-only mode remains `detect_only`; native-shell sandbox mode remains deferred with `cannot_see` interior. UI labels cannot promote one into the other.
- [ ] Test opt-in installation/removal of the owned menu key using realistic JSONC comments, unknown fields, malformed content and concurrent user changes. Preserve all unrelated content; unsafe parse leaves the file untouched with a reviewable proposal. Desktop entry `Exec` is literal and resolves to the installed opener; optional icons must be packaged.
- [ ] After O6 publishes and installs the locked candidate, execute current I01-I08 against that exact installed host/plugin/backend through the owning qualification harness. Keep ordinary protected-entry activation disabled until the first sealed W1 release is recorded and this protected tuple passes its own later O7 promotion. Run unknown default, stale executable, removed plugin, failed hook and missing native gateway negatives. Return the installed-candidate acceptance record to O7; six menu labels are not six accepted integrations.
- [ ] With a protected candidate that passes I01-I08, omit the sealed-release record and assert production activation and protected promotion both refuse. Complete O3/O6/O7 sealed qualification/promotion while O5 remains unavailable, then verify that only the exact separately accepted protected tuple can advance. Retain the sealed public tuple and qualification/promotion evidence as the release-order prerequisite; an O3 development run, candidate publication or protected-host pass alone cannot satisfy it. Observe, approval and stop retain their independent release gates throughout.

Future check:

```bash
python3 -m unittest discover -s tests/integration/omarchy -p test_host_launcher.py -v
```

**Acceptance:** The protected action coexists with upstream defaults and launches only individually qualified, promoted protected adapters after the first sealed W1 release. Candidate work proceeds independently without production activation. Host count, exact qualification evidence and the predecessor sealed-release record are visible.

## Packet O6: Build packages and publish qualification candidates

`boundary_class: prevent` for trusted activation/integrity gates; `advisory_only` for release metadata.  
`planning_status: ready_after_adr`  
`execution_gate: candidate build/publication requires O1/O2 deliverables, implemented selected-profile components, verifiable source/package identities, real public destinations and publication authorization; final I08 or release qualification is not required to publish an explicitly unqualified candidate. Sealed production activation consumes its O3/O7 evidence independently of O5; protected activation additionally requires the first sealed release and its own later O5/O7 acceptance.`

**Files:** Create `packaging/omarchy/PKGBUILD`, `packaging/omarchy/README.md`, `packaging/omarchy/units/`, `packaging/omarchy/tests/test_package_contents.py`, `packaging/omarchy/tests/test_plugin_delivery.py` and generated candidate inventories in the existing release system. Use its signed manifest/provenance format. Do not introduce another schema family solely for these documents.

- [ ] Package the shared controller plus required platform shim/opener, units, desktop entry, menu fragment, optional icons and diagnostics docs. Record final package/binary names from actual implementation. Native/runtime dependencies are separate declared inputs with exact public identities; no build/install self-download or ambient runtime resolution.
- [ ] Produce a standalone public Git delivery tree with the QML plugin manifest and complete assets at repository root. Map canonical source to delivery commit and full file/mode inventory. Verify all imports/assets, release-compatible manifest fields and no credentials/developer paths. Pair the plugin with the exact native/common-protocol tuple.
- [ ] Build twice in independently recorded clean Arch chroots using locked public sources. Compare extracted package contents and retain `.BUILDINFO`, SBOM/license inventory and signed provenance. Record mismatch as failed reproducibility, not an assumed property of using devtools.
- [ ] Add archive tests for missing/altered opener, controller, unit, desktop entry/menu fragment/icon, wrong mode/owner, setuid/setgid bits, unexpected executable, shell-based `Exec`, install-time enable/linger and package scripts writing user state. Every delivered file must appear in the reviewed inventory.
- [ ] Publish an explicitly unqualified candidate using real release-system destinations and approved publication procedure before final installed-host I08 acceptance. Keep unqualified protected/execution controls disabled. Verify anonymous public retrieval of every source/revision/archive/signature and complete inventory. The selected-profile clean-host campaign consumes this candidate; a sealed candidate can complete O7 without O5. Protected activation/promotion additionally waits for O5's installed-host evidence and the already promoted first sealed W1 release. If publication is unavailable, retain the blocker without inventing a URL or claiming install qualification.
- [ ] Test the selected installed Omarchy add contract. Verify no existing `computer.chio.desktop` directory/ID/persisted enablement. Obtain the repository URL, 40-hex public delivery commit and inventory from the verified lock; `--yes` without `--enable` must leave the plugin disabled.

Future build and package checks:

```bash
cd packaging/omarchy
extra-x86_64-build
python3 -m unittest discover -s tests -p test_package_contents.py -v
python3 -m unittest discover -s tests -p test_plugin_delivery.py -v
```

Set up and record clean-chroot inputs before running `extra-x86_64-build`. Tests consume the actual built archives through their documented interface, implemented before these commands are considered runnable.

On the owned clean host, after verifying the lock and absence of existing plugin/enablement, use these real upstream interfaces with validated values:

```bash
set -eu
plugin_install_dir="$HOME/.config/omarchy/plugins/computer.chio.desktop"
omarchy plugin add "$plugin_repository_url" --yes
git -C "$plugin_install_dir" checkout --detach "$plugin_public_revision"
test "$(git -C "$plugin_install_dir" rev-parse HEAD)" = "$plugin_public_revision"
test -z "$(git -C "$plugin_install_dir" status --porcelain)"
omarchy plugin validate "$plugin_install_dir"
```

- [ ] Before enabling, independently compare the complete installed path/mode/content inventory with the signed lock, including plugin ID, manifest, protocol and paired native identities. Recheck disabled state. A clean Git status is insufficient. Missing locked commit, wrong signer/inventory, unexpected file, changed asset or incompatible pair leaves the candidate disabled.
- [ ] Only after successful inventory and state checks run `omarchy plugin enable computer.chio.desktop`. Retain real load/service/bar/panel observations. First test plugin-only absence of backend, then explicit native-package onboarding; no automatic task or credential creation in either case.
- [ ] Move the public default branch after locking; alter an asset, remove the locked commit in a controlled delivery fixture, substitute inventory/signature and change the protocol pair. The process reproduces the lock or refuses before enablement. Never invent Omarchy `--revision`, `--ref` or archive-install options. Upstream plugin update is an independently changing input requiring requalification, not a substitute for this sequence.

**Acceptance:** Another operator can retrieve the exact candidate without private credentials/developer files. The plugin remains disabled until full inventory and compatibility verification. Candidate publication is explicitly unqualified and does not imply O7 completion.

## Packet O7: Independently qualify lifecycle and promote only passing profiles

`boundary_class: detect_only` for independent observations; `prevent` for activation refusal being tested; `advisory_only` for support claims.  
`planning_status: ready_after_adr`  
`execution_gate: publicly retrievable O6 candidate, actual x86_64 Omarchy and every predecessor gate for the explicitly selected profile. Sealed qualification/promotion consumes O3 without O5. Protected qualification may run in parallel, but production activation/promotion requires the first sealed W1 release record and the protected tuple's own O5 I01-I08 evidence. Observe/approval/stop remain independently eligible.`

**Files:** Create `tests/integration/omarchy/test_distribution_lifecycle.py`, `tests/integration/omarchy/test_fault_recovery.py`, `tests/integration/omarchy/test_diagnostic_privacy.py`; retain raw real-host evidence under the existing release/qualification system and a concise `integrations/omarchy/acceptance/README.md`. Extend owner/shared harnesses for missing capabilities; do not reintroduce the retired Omarchy validator/fixture tree.

- [ ] Have an independent tester start from the exact clean Omarchy installation with no development checkout. Capture installed tuple, public source retrieval, package/signature verification and full plugin loading. Execute observe and every additionally selected work/approval/protected-host profile through the real launcher. Unavailable profiles remain excluded by name and unavailable in product UI.
- [ ] Change one tuple dimension at a time: plugin, native binary, Node/library/image, provider route, engine/CLI/runtime, daemon privilege mode, socket/client/daemon config, UID/GID maps, unit override, kernel or required namespace/cgroup feature. Insert hostile `node`/`chio`/`mise` shims first in PATH. Admission must refuse relevant mismatches before effects, and canary executables must remain unexecuted. Repeat after Omarchy's post-update hook and later runtime updates. Explicitly replace the selected rootless endpoint with a rootful endpoint and remove rootless prerequisites; assert refusal without rootful retry.
- [ ] Upgrade with active and unknown operations. Interrupt package extraction, migration preflight/write, tuple activation and recovery start. Use owner-defined migration/backup semantics and original identities. The outcome is a coherent valid tuple or explicit unavailability with recovery steps, never mixed-generation execution or repeated effects.
- [ ] Test compatible/incompatible code rollback and an actual root snapshot rollback with newer home/plugin state. Receipt anchors, reservations, revocation and external-effect knowledge cannot move backward. An old binary refuses incompatible writes; a missing recovery binary stays a failure rather than deleting state.
- [ ] Back up idle and unknown work with the owners' consistency APIs. Restore valid, corrupt, stale pre-effect, path-traversal/symlink and missing-key/anchor cases. Stage safely, verify inventories and reconcile with current native originals/external counters before effects. Do not label an offline native authority or copied live SQLite file as recovered.
- [ ] Inject ENOSPC/inode exhaustion, EIO, read-only state, interrupted package installation and missing cached recovery package. Assert clear diagnostics, no silent journal reset and preserved unresolved custody. Authoritative receipts/fences do not disappear under operational-log retention limits.
- [ ] Repeat O3's silent storage and stdout/stderr overload with stalled consumers, concurrent tasks and outside-container engine logs against the installed tuple. Verify the actual host quotas, aggregate reservations, output ingress/retention and protected receipt/controller/stop headroom, plus bounded cleanup and honest unresolved outcomes. Remove or weaken each required limit independently; execution admission must refuse before effects.
- [ ] Disable/reload/remove the plugin, stop/remove the backend and attempt purge with unresolved work. Bounded stop and owner recovery retain user projects, artifacts, anchors, backups and unresolved records. Only package-owned files/explicitly owned menu keys disappear; no unrelated user service, shortcut or configuration is modified.
- [ ] Test signed runtime revocation and a qualified successor. New admissions stop for the affected tuple; unsigned replacement fails; replacement does not auto-resume or broaden authority. Package signatures establish integrity/publisher, not confinement or source qualification.
- [ ] Run sustained observation with panel visible/closed, many widgets and disconnects. Measure CPU/RSS/IPC volume and enforce common queue/frame/backpressure caps. No per-widget polling or recovery-inspection loop. Flood diagnostics and seed secrets/source/path canaries; bounded local export reports omissions and performs no automatic external upload.
- [ ] Repeat O1-O5's actual platform cases for selected profiles, including subreaper refusal/cleanup, approval direct-binary negatives and six-host I01-I08 scopes. Bind all evidence to the installed hashes. Missing required results, skipped real-host tests, stale pins or failed cleanup leave the profile unqualified.

Future checks on the qualification host:

```bash
python3 -m unittest discover -s tests/integration/omarchy -p test_distribution_lifecycle.py -v
python3 -m unittest discover -s tests/integration/omarchy -p test_fault_recovery.py -v
python3 -m unittest discover -s tests/integration/omarchy -p test_diagnostic_privacy.py -v
```

The implementation must expose real-host prerequisites and test outcomes through the shared qualification system. A unittest process exit alone is insufficient if required cases skipped. Verify evidence through the actual shared verifier command recorded in O0, then inspect independent oracles and negative controls.

- [ ] Publish the concise qualification report: exact profiles and hosts, public artifacts, tested host tuple, passed/refused/unknown/skipped cases, limitations, independent reviewer and reproducible commands. Promote only passing tuples through the release owner. Record the first sealed W1 release from O3 composition plus O6/O7 installed evidence before any protected production activation or later protected promotion; that sealed promotion does not depend on O5. Protected promotion verifies both the predecessor sealed-release record and its own exact installed I01-I08/release evidence. Observe, approval and stop may promote independently. Public instructions name only verified public Chio source/revisions and actual artifact URLs. They do not expose internal working-repository names or private-only commits.
- [ ] Finish installation, upgrade, rollback, diagnostics, restore and uninstall documentation against the observed behavior. Document failure/recovery commands from actual delivered interfaces and make unsupported profiles visibly unavailable. No fictional runtime commands or inferred platform coverage may remain.

**Acceptance:** Public install and real operation reproduce independently on the named tuple; fault and negative cases preserve native custody and prevent unqualified activation. Local source checks, candidate availability, runtime qualification and release promotion are reported as separate outcomes.

## Completion and scope control

- [ ] Check all new local documentation links and `git diff --check`; search for retired platform protocol names, old P4/P5 execution promises and private public-install instructions.
- [ ] Review source/API ownership against the program map. Any new runtime concept, custom task state, recovery retry loop, signing authority, peer-auth stack, sandbox or subprocess runner returns to its owner for consolidation.
- [ ] Confirm the workbench is the first operator client, sealed W1 work is the first execution product, approval gates remain intact and the protected-launch program names all six hosts with individual I01-I08 evidence.
- [ ] Record packet completion only against actual evidence. A checked plan, passing schema, mock controller or research record cannot qualify an installed profile.

No packet implements compositor tools, configuration repair, desktop-private delegation or a general agent sandbox. A future boundary-interactive profile requires its own owner-approved backend/host qualification and `cannot_see` workspace label before this plan can be expanded.
