# Omarchy platform annex

Status: accepted platform direction under [ADR-0038](../../../adr/ADR-0038-desktop-operator-program.md); implementation and runtime qualification remain open. This annex replaces the former numbered Omarchy specifications. Confidence: high in the ownership and evidence boundaries; moderate in platform feasibility; unknown for the complete installed Omarchy composition.

Chio is a modern Rust kernel for agentic operating systems. On Omarchy, the desktop program makes its work, authority and evidence usable through the common workbench and a small native shell surface. It adds Linux packaging, session integration and presentation to the [shared desktop program](../2026-10-07-desktop-integration/README.md).

Read the [program map](../../../architecture/PROGRAM-MAP.md), proposed [shared operator protocol](../2026-10-07-desktop-integration/OPERATOR.md), [qualification contract](../2026-10-07-desktop-integration/QUALIFICATION.md) and [implementation packets](../../plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md) with this annex. The program map identifies the predecessor owners; names such as S4, S5, S7, S8, S28, W1 and doc 19 below refer to those owners, not new Omarchy APIs. No installer, package, service or supported runtime is delivered by these documents.

## Product and boundary scope

| Surface/profile | `boundary_class` | `planning_status` | Admission and claim boundary |
| --- | --- | --- | --- |
| Operator navigation and diagnostics | `advisory_only` | `ready_after_adr` | Workbench first; QML displays qualified owner projections and opens views. Navigation never grants authority. |
| Hook-mode host observation | `detect_only` | `ready_after_adr` | Show actual host/plugin provenance and observation gaps. Hook absence, timeout or crash can leave a tool running. |
| Sealed W1 work | `prevent` | `ready_after_adr` | Only qualified kernel-owned tools/egress are mediated. W1 single-owner unpaid work, fixed recipe and acceptance, S7 backend evidence and current host gates are prerequisites. |
| Native approval and per-task closure | `prevent` | `ready_after_adr` | Only owner-provided pre-effect decisions and S4 closure; attributable approval requires S28, a production passkey verifier and the installed Pi utility fix. |
| Protected interactive host | `prevent` | `ready_after_adr` | Doc 19 protected mode removes the native shell; production activation and promotion require the first qualified sealed W1 release and that host's exact installed I01-I08 combination and release acceptance. Candidate development may proceed independently. |
| Boundary interactive: gateway-routed calls | `prevent` | `deferred` | Only calls actually authorized before dispatch qualify; denying bypass routes and containing descendants require independent evidence. |
| Boundary interactive: shell/workspace interior | `cannot_see` | `deferred` | Native-shell writes allowed inside its sandbox have no per-write Chio decision or receipt. |
| Arbitrary desktop/compositor control and configuration repair | `cannot_see` | `hard_skip` | Former P4 and P5 are removed from this desktop program. |
| Delegated and multihost work | `prevent` | `deferred` | Kernel/work/process owners define it; this annex supplies no child runner, custody handoff or desktop delegation protocol. |

`planning_status` follows [ADR-0011](../../../adr/ADR-0011-boundary-taxonomy-product-wording.md). `ready_after_adr` means the accepted direction permits planning; it is not execution readiness. The shared qualification contract supplies the delivery gates. Current runtime claims remain unqualified.

The mandatory host program is Claude Code, Codex, Cursor, Hermes, Pi and OpenClaw. Pi goes first because of the recorded restricted-session evidence, not because the shared contract is Pi-specific. Historical plugin 0.1.0/Pi 0.85.1 observations do not qualify the newer plugin/Pi combination or Omarchy. No other host inherits a pass from Pi. Observing all six is useful before protected execution is accepted for all six.

The first execution experience is one sealed work commitment: select an enrolled project, review a bounded request and fixed verification recipe, run through the owning stack, review the patch and acceptance evidence in the workbench. Execution, acceptance, result, recovery, settlement and delivery remain independent `WorkViewV1` observations. A completed process, a passing recipe and an accepted deliverable are different facts. Editing or publishing the developer's checkout is a separately authorized owner operation, never an implied consequence of a successful task.

Release order enforces this product choice: O3 supplies the sealed composition, O6 publishes its unqualified candidate, and O7 qualifies the installed tuple and records its promotion as the first sealed W1 release. That promotion does not wait for O5 protected-host acceptance. Protected candidates may be built and tested from O1/O2 in parallel, but their production activation and later O7 promotion must verify that sealed-release record as well as their own host gates. Observe, approval and stop remain independently eligible under their own prerequisites; this ordering does not add a sealed-work gate to them.

## Architecture and ownership

One C-layer controller serves the workbench, existing Chio CLI, Omarchy QML and macOS clients through proposed `chio.operator.v1`. It runs outside the TCB and owns no signing keys, authority store, approval issuer, trusted fact assertions or independent execution journal. The gateway and process host remain separate processes inside their established trust boundaries. Omarchy supplies deployment and UI adapters for this same controller, not a platform fork.

The first Linux delivery supports one explicitly enrolled graphical login session per UID. Bind that controller instance to the native-verified UID, boot identity and logind session, and bind each client to that same session through the qualified IPC/browser enrollment owner. A per-user systemd manager or socket is not proof of a login session. Refuse enrollment/connections from a second concurrent session, even for the same UID; no silent reassignment after logout or restart. A lingering manager does not preserve session authority. Lock, logout, unknown liveness and missed observations disable affected disclosures/actions; any requested closure is restricted to native owner references belonging to the bound session, never other sessions' work. Session replacement needs explicit enrollment and reconciliation of the original custody. Multiple independent sessions require a later per-session service design and qualification.

| Omarchy integration need | Existing owner and required reuse |
| --- | --- |
| Tasks, fixed request, acceptance and projections | W1 `WorkHandleV1`/`WorkViewV1`; workbench task/worktree/review flows. |
| Original-operation lookup and recovery | Recovery `InspectWorkflow`, `SubmitApproval`, `ResumeWorkflow`, `CancelWorkflow`, plus W1 queries and S9 M20 retry classes. Do not synthesize a replacement operation after an unknown effect. |
| Event delivery | S5 Part B, triggered by the desktop as a second consumer; Part A transport fixes are a prerequisite, not stable subscriptions. Basic Observe uses the selected trust-control/hook sources; recovery read/event adapters qualify only when recovery views or hints are exposed. No platform polling loop over `InspectWorkflow`. |
| One-task stop | S4 phases 1 and 2 closure, rendered with owner result kinds; previously admitted effects can remain unresolved. |
| Durable emergency stop | S8 phase 1 supplies durable `Kernel` stop and S30 routes/results; `Tenant` and `Recovery` wait for phases 4 and 5. None is an alias for per-task closure. |
| Identity and approvals | S8 S28 phase 3 production operator roster and production passkey verification. Until qualified, any owner record with `SharedCredential` attribution keeps that label. |
| Local peer authentication | Linux `SO_PEERCRED` through `chio-secure-ipc`; do not write a second peer-credential stack in the shim. |
| Child custody and termination | `chio-process` and `ProcessRegistry`; systemd provides host lifecycle/cgroup enforcement, not a competing task model. |
| Credentials and provider access | `chio-secret-broker` plus the existing model relay; no desktop-specific credential proxy. |
| Sealed coding | Reuse `chio-mini-swe` and its networkless workspace/mediated `sandbox/execute`, Pi's restricted session/coding resource, and workbench review. Rootless Docker is the first engine candidate to qualify with the existing runner; rootless compatibility is not established. Extend their owners where needed. |
| Isolation evidence | S7 and thin backend adapters. Isolation denies access; Chio grants access through its gateway/resources/relay. |

Predecessors may be sequenced as delivered inputs for planning. Implementation binds exact available revisions and acceptance records before consuming their APIs. Basic receipt/hook observation uses the shared Observe lane: S5 and the selected authenticated read/source-attribution adapters. W1 views, recovery views/events or actions, approval, stop and execution add only their own mapped prerequisites. Basic Observe must qualify with W1/recovery owners absent: their optional views and hints remain unavailable, and no reads or subscriptions target them. Those selected functions consume W1, recovery fixes, S3 phase 1, S4 phases 1 and 2, S7, S8 phase 1/S28, S9 M20 and applicable S10 crossing behavior; their absence cannot block the basic Observe candidate. The desktop does not require the NK-01 to NK-03 keystones. S11 becomes a prerequisite only for a later injection-safety claim.

### Linux backend composition

Use the Pi restricted bubblewrap profile as the initial agent-host candidate and reuse the Docker-based `chio-mini-swe` path for the sealed workspace. The default qualification candidate is **rootless Docker**, retaining the existing runner's exact CLI/API contract where it proves compatible. No inspected mini-swe result establishes rootless qualification. Run its real source/edit/test/artifact flow and independent confinement, custody and resource checks on the selected x86_64 Omarchy installation before enabling it. Missing rootless prerequisites, incompatible runner behavior or ineffective limits make the profile unavailable; there is no fallback to rootful Docker, sudo or an unrestricted process.

Both pinned Omarchy revisions install Docker and enable its system socket, but explicitly withhold default docker-group membership; Sudoless Docker is a separate opt-in. Existing installations must be measured. Access to the rootful daemon through the `docker` group is root-equivalent. If supported at all, that path requires a separately selected, explicitly documented privileged profile whose trusted host-side runner and root daemon are in the containment TCB. A non-root CLI UID or `userns-remap` does not make that daemon rootless. This changes the trusted host exposure, not Chio's authority owner: kernel/work/resource owners still grant operations; neither engine, controller nor QML becomes an issuer. [Pinned Omarchy posture and engine research](research/linux-platform.md#container-engine-privilege-and-compatibility)

Rootless Podman is a separate candidate, not a drop-in alias. Inventory the runner's actual CLI/API, archive/copy, exec, exit/stream, image, mount/UID-map, network, stop/remove and custody requirements, then qualify the selected Podman version against them. Its Docker API compatibility layer alone proves no runner equivalence. Any necessary adaptation belongs to the existing runner/backend owner. An engine change creates a new qualification tuple.

Only the qualified trusted host-side runner may access the selected engine endpoint. Agent guests and test recipes receive neither engine sockets (including rootless sockets), API credentials, inherited connected FDs nor docker-group privileges. Strip inherited privileged group access and verify the resulting credentials; socket omission alone is insufficient. Bind the runner to the measured local endpoint and effective configuration; ambient Docker contexts, `DOCKER_HOST`/`DOCKER_CONTEXT`, user config or a substituted socket must not redirect it. Rootless engine access still permits powerful actions as its host user and is not a boundary against malicious trusted same-user desktop software. Inventory any coexisting rootful daemon and prove that the Chio runner and guests cannot reach it under the rootless profile. Installation does not silently change upstream group membership, disable unrelated Docker workloads or enable lingering.

Before admission, the runner/resource owners enforce finite per-task and aggregate budgets for writable volume/layer bytes, temporary/cache data, inodes, stdout/stderr ingress and buffering, retained output and engine logs. Inventory the actual host storage and sinks, including Docker daemon/container logs, journals and spool files outside container filesystems. A read-only container root, tmpfs byte cap or client output cutoff alone cannot qualify those other surfaces. Map concrete quota, output and admission APIs through O0; missing enforceable bounds make the profile unavailable. Reserve sufficient host capacity for receipts, original-operation state, stop/recovery and the controller under concurrent tasks. Independent host quota/usage and sink measurements must prove the configured limits and headroom. Silent disk/inode exhaustion, separate and combined stdout/stderr floods, stalled consumers and concurrent-task pressure must refuse new admission or stop affected execution before that reserve is consumed. Cleanup must remain bounded and independently observed; unresolved resources retain custody, and authoritative evidence is never deleted to make room or replaced by a false successful result.

The S7 owner must add or qualify the `AgentHostBwrap` evidence kind before the desktop renders that claim; `ProcessContainer` covers a qualified container backend. OpenShell is a later external-runtime adapter once its contract and evidence are stable. Missing/unknown backend evidence renders the owner-defined unconfined/unavailable state. QML and the controller cannot mint evidence or infer confinement from a process name, successful launch or manifest.

`chio-cage` remains a specific tool-server profile. Its inspected x86_64, Landlock and syscall constraints do not run Node/Pi; this program neither forces Node into it nor relaxes its policy. A tool-server cage receipt is not evidence for the whole agent. Preserve separate inventories for agent, trusted resource and test recipe, including exact runtime/loader files, mounts, descriptors, namespace behavior and effective filters. The historical privileged ARM64 bubblewrap run is research evidence, not native Omarchy acceptance.

Agent access is limited to the qualified gateway/model-relay descriptors and selected workspace/runtime closure. No operator endpoint, provider secret, authority store, SSH agent, desktop bus, compositor socket or container-engine socket crosses into the agent. Measure filesystem, raw network, inherited descriptors and subprocess escape attempts from outside the guest. A hook plugin cannot close these routes.

Test harness cleanup belongs to the shared Linux qualification/process tooling. Preserve the Linux child-subreaper lesson: a dedicated fixture worker establishes and verifies child-subreaper custody before starting hostile descendants, remains alive during bounded cleanup, and reports unavailable custody as a prerequisite refusal. It must not silently change the controller or shared orchestrator's subreaper state. Exercise double-fork, process-group escape, detached descendants, full stdout/stderr pipes, timeout, stop escalation and orphan reaping. Independent process/cgroup observations must establish absence; worker exit or a returned timeout is insufficient. Failed cleanup retains unresolved custody and fails the case. This acceptance requirement does not authorize another Omarchy-private process runner.

## Omarchy shell contract

The first native shell surface is an optional thin plugin with ID `computer.chio.desktop`, `bar-widget`, `panel` and `service` kinds and `keepLoaded: false`. It shows receipt/hook status, boundary labels, connection state and navigation to the workbench. Task/recovery counts and hints appear only when their separately qualified owner views are exposed. The workbench owns task creation, project intake, editing and full patch review. Small QML approval/stop affordances may be added only after the shared native paths qualify; they do not replace the browser client or reproduce its task editor.

The retained [upstream research](research/omarchy-upstream.md) pins release v4.0.4 at `c668141e9c42b13c80c9ca4ea108e11708c5e8a5` and observed development HEAD at `0f8af9be307d5d4f12cc0f6394892cac651ed5e6`. They are separate compatibility candidates. Neither is qualified by this specification, and a source revision does not freeze installed Arch packages.

| Platform behavior | Required adaptation |
| --- | --- |
| `shell` and `manifest` are injected after QML object creation | Start one client only after required properties are ready; repeated injection is idempotent. `Component.onCompleted` alone is insufficient. |
| Reload destroys nonretained services, widgets and panels | Generation-bound callbacks; disconnect and terminate only the presentation shim. Reconnect to existing work without replaying commands. |
| Bar widgets can exist on several monitors | One service subscription shared by all widgets; no per-monitor controller/client or polling fallback. |
| Replacement bars may omit own-service access | First qualification requires `omarchy.bar`; show unavailable state when absent. Do not bypass facades by traversing QML parents. |
| A panel kind receives queued navigation payloads | Strict navigation-only routes and opaque owner IDs; repeated opens are harmless. No paths, commands, tokens or approval bodies in summon payloads. |
| HEAD has helpers/types absent in v4.0.4 | No unconditional `ShellIpc` or `Style.duration` use; feature probe with static/reduced-motion fallback. |
| Notifications persist with click actions | Generic text, `app_name=Chio`, normal urgency and a fixed opener only; respect DND. Historical clicks refresh current owner state. |
| Third-party QML is desktop-user code | Trust installed desktop plugins and the user in this threat model. Facades and socket modes do not isolate malicious same-UID plugins. |

Use upstream `Color`, `Style`, `Border` and supported panel primitives. Supply Accessible names, roles, states and actions; text plus shape for status; explicit keyboard focus and reduced motion. Suspend `PanelKeyCatcher` interception while an editor/IME owns input. Real acceptance includes keyboard, screen reader/AT-SPI, large text, theme changes, IME, multi-monitor focus and lock privacy. Importing an accessibility type does not prove accessibility.

A small package-owned client shim may connect QML to the shared controller where needed. Use literal absolute argv and bounded stdin/stdout streams with the common protocol codec. It has no auth policy or special direct native API. Pass no prompts or secrets through argv, inherited environment, notification actions or journald. The common transport owns framing, version negotiation, backpressure, request binding and resynchronization; the plugin consumes those semantics and rejects stale generations. Do not restate a platform-specific method catalog, event cursor schema or recovery database here.

QML stores visual preferences only. Native/workbench owners retain durable work, original-operation and artifact state. Clear sensitive in-memory details on lock, unknown lock state and relevant disconnects. A fixed opener accepts only allowlisted views and owner IDs and cannot authorize, resume, publish or open task-supplied executable content. No plugin self-installation, package-manager invocation or unattended secret import is permitted.

### Launch paths and the six hosts

The upstream launcher uses hardcoded agent cases. Its auto-approved modes, including permission-skipping flags where present, are not Chio protection. Upstream Agents usage/subscription UI remains useful and independent of Chio authority. Do not shadow `pi`, replace `omarchy-agent`, change the selected default agent or edit upstream aliases and bindings.

Provide a package-owned desktop/Walker entry and optional owned menu action, **Launch default agent in protected mode**. This is an opt-in Chio entry, not a modification of the upstream launcher. Resolve the user's selected host through the inspected platform adapter, display it, then require a matching doc 19 I01-I08 acceptance tuple for that host/version/plugin/backend. Production activation additionally requires the recorded first sealed W1 release and the protected tuple's later O7 promotion. Unsupported selections explain why and offer an explicitly chosen qualified host; they never silently launch the native auto mode. Host identity and qualification are rechecked at launch. Until the protected entry qualifies and its release gates pass, expose only the ordinary Chio workbench opener and accurate unavailable status.

Install menu customization only through explicit onboarding using one owned static key and a literal opener. Preserve unrelated user JSONC, comments and shortcuts. Unsupported syntax produces a proposed edit and leaves the file untouched. Walker/desktop visibility and the menu guard are convenience, not authorization. Existing keyboard shortcuts remain the user's; a custom shortcut requires an explicit choice and collision check.

## Session, service and operational lifecycle

Package the shared controller as a systemd user service. Installation places inert unit files; onboarding explicitly activates the operator surface. Do not enable lingering, import the user's entire environment or create a root controller. Verify actual `graphical-session.target` and logind behavior on the selected Omarchy, including a user manager already configured to linger. Do not equate the user manager's survival with a live authorized desktop session.

| Transition | Required owner interaction and observable result |
| --- | --- |
| Plugin load, unload, reload or theme change | Presentation connects/disconnects only; native work identity survives and no task, approval or stop is synthesized. |
| Controller crash/restart | Reconnect through shared transport, reload native projections and unresolved originals; no automatic new work or replay. Native custody is owned by `chio-process`. |
| Lock or unknown lock state | Conceal sensitive UI and disable new operator mutations; admitted work may continue only within its existing expiry/scope and selected qualified policy. |
| Unlock | Fresh identity/session, compatibility and owner snapshot; no extension of approval/capability expiry. |
| Suspend/resume or clock uncertainty | Host adapter invalidates stale observations; native owners enforce the boot-associated `CLOCK_BOOTTIME` task deadline and authority-issued absolute expiry, then reconcile/revalidate before new effects. Resume, realtime rollback or restart cannot renew authority or replay work. |
| Logout/session loss | Stop new admission and use S4/process custody for bounded local termination, retaining unresolved effects. Must hold with lingering enabled and missed events. |
| Per-task stop | Invoke S4 closure, render actual result and independently verify descendant termination where claimed. Do not imply an external effect was undone. |
| Broad emergency action | Use S8 phase 1 for `Kernel`; later `Tenant`/`Recovery` scopes require phases 4/5. Preserve the distinction from one-task closure and the current unqualified process-local implementation. |
| Credential store lock/removal | Broker and relay refuse affected new access; preserve unresolved operations and receipts. No plaintext fallback. |

Keep controller, trusted relay/launcher and guest/resource units separately scoped where required by their existing owners. Use role-specific tested hardening, bounded restart/stop behavior, restrictive umask, core-dump suppression, measured cgroup resource limits and fixed executable paths. A unit option unsupported in the user manager must not become silent partial protection. Hardening that disables namespaces or required Node threads cannot be fixed by removing all confinement. A systemd analyzer score is supplementary evidence; effective kernel properties and negative probes decide acceptance.

The existing authority/work/runner/process owners must define and qualify the
actual Linux clock contract before an execution profile is enabled. Bind local
task lifetime to boot identity and a `CLOCK_BOOTTIME` deadline that includes
suspend; retain the authority-issued absolute expiry as a separate bound.
`CLOCK_MONOTONIC` alone does not measure suspended time, and realtime adjustments
cannot reset or extend the retained task deadline or revive expired authority.
Record the actual owner clocks, conversion/check points, persistence and restart/
boot-change reconciliation in O0; do not add a desktop timer or clock protocol.
Expiry or an unprovable clock/boot basis fences new protected dispatch and
continuation and invokes the owner's bounded closure/custody policy. On resume,
the native fence must hold before untrusted continuation until owner revalidation;
a delayed UI or userspace observation is insufficient. An already dispatched
external effect may still complete and is reconciled separately, never asserted
undone by expiry. Missing native
clock enforcement disables the dependent execution profile, not basic Observe;
observation still qualifies its own read authority and freshness. This carries
the [Linux clock research](research/linux-platform.md#upstream-linux-conclusions)
into a required implementation and installed-qualification contract.

Bound each stop and cleanup phase with an explicit selected-profile deadline. If complete process absence or original outcome cannot be established, render the owner's unresolved state and preserve recovery custody. Neither SIGKILL nor a clean systemd state proves absence of a remote effect.

## Packaging, compatibility and distribution

Three delivery roles are separate: the shared controller/native dependencies, the Omarchy platform package (shim/opener/units/desktop registration) and the QML Git plugin. Final Arch package names are a packaging decision, not available product commands. Use pacman-compatible signed artifacts with fixed public source inputs, package hashes, dependency/runtime inventory, license/SBOM provenance and build records. Never resolve the protected runtime through `mise`, ambient `PATH` or an unrecorded developer checkout.

The shared native package/dependency inventory includes the existing `chio` CLI
operator consumer from shared packet 4a, with its exact executable/source identity
and controller/common-protocol pairing. An unqualified candidate may be assembled
and published before final CLI acceptance. Program completion and CLI-support
claims require source and installed-client evidence; a platform opener or protocol
probe does not deliver the promised CLI. Useful baseline Observe must work without
absent W1/recovery/execution owners, and selected actions add only their own gates.

The support record binds one explicit profile to the following tuple:

- Public Chio owner sources and exact controller/native/bridge/operator binaries; work/operator/state ABIs and acceptance records.
- Omarchy revision, installed Quickshell/Qt/Hyprland/systemd, architecture, kernel and effective namespace/cgroup/LSM probes.
- Plugin delivery commit and complete file/mode inventory; common protocol version and required shell features.
- Agent/plugin/runtime lock, backend/image/runtime closure, gateway/resources, policy, fixed recipe and verification identities.
- Engine/CLI/API and container runtime identities, runner binary/launch identity, daemon rootless/rootful mode, host UID/GID/supplementary groups and measured user-namespace UID/GID maps; subordinate-ID ranges and mapping-helper identities.
- Engine socket endpoint/ownership and effective client/daemon configuration digests, service units/overrides, storage/network/rootless-helper identities, mounts and image digest. Required cgroup v2 controllers/delegation and observed limits are bound to this same profile, not inferred from accepted flags.
- Finite per-task and aggregate writable-byte/inode quotas and output ingress/buffer/retention limits, actual host storage and engine-log sinks, native enforcement identities, admission reservations and independently measured receipt/controller/stop headroom.
- Provider/model route and account binding, supported enforceable limits and unavailable dimensions; credential custody profile.
- Session adapter and effective unit definitions/overrides, including graphical-session and lingering behavior.
- For execution profiles, the actual native clock/deadline implementation, boot-identity binding, suspend-inclusive local lifetime, authority absolute-expiry checks and restart/clock-uncertainty reconciliation evidence.

Source presence, historical tests, a valid manifest and package signatures are separate facts from a supported tuple. The read-only diagnostics path may operate on an unknown tuple if its own transport is compatible; affected execution stays unavailable. Report the changed dimension instead of turning a healthy daemon into an execution-ready claim.

Omarchy's post-update hook can invalidate compatibility, but it runs before later runtime updates and cannot certify final compatibility. Remeasure at startup, reconnect and admission using the shared integrity gates. Modified QML, an updated library, changed unit override or kernel reboot invalidates relevant acceptance until the qualified replacement is installed. Ordinary host security updates need not be blocked to preserve Chio availability.

### Public candidate installation and promotion

Publish independently retrievable, explicitly **unqualified qualification candidates** before the clean-install campaign; supported release promotion follows that campaign. O7 first promotes the qualified sealed W1 execution tuple without requiring a protected-host release. A later protected-host promotion references that sealed-release record and its own installed acceptance; candidate publication alone satisfies neither gate. Observe, approval and stop can qualify and promote independently. The release record must contain real public URLs and revisions before commands are generated. These documents intentionally provide no invented plugin repository or native package URL.

The inspected `omarchy plugin add` accepts a repository URL and `--yes`, not a revision selector. `--yes` without `--enable` installs disabled. The clean-host procedure is:

1. Verify the signed public candidate lock and obtain its repository URL, full delivery commit and independent file inventory. Confirm that the plugin ID/directory and persisted enablement do not already exist.
2. Run `omarchy plugin add "$plugin_repository_url" --yes` with values from that verified lock. Do not pass `--enable`.
3. Select the exact public commit using `git -C "$plugin_install_dir" checkout --detach "$plugin_public_revision"`. Verify HEAD, the expected ID, all file paths/modes/digests (excluding Git metadata), absence of unexpected files, compatible native/plugin pair and disabled state. A clean Git status alone proves none of these identities.
4. Run `omarchy plugin validate "$plugin_install_dir"` for the selected installed Omarchy. Only then explicitly run `omarchy plugin enable computer.chio.desktop`.
5. Observe real shell loading and native connectivity. Plugin installation/enablement does not install the backend, create credentials or start an agent. Repeat plugin-only/missing-backend and incompatibility cases independently.

The pinned [release add](https://github.com/omacom/omarchy/blob/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/bin/omarchy-plugin-add), [development add](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-plugin-add) and [enable](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-plugin-enable) sources define that interface. Recheck installed behavior before delivery. Do not invent `--ref`, `--revision`, archive-install flags or a Chio permission field in the Omarchy manifest. Upstream update can change the Git plugin independently; changed content requires verification/activation again and may refuse on a detached checkout. It never preserves qualification by assumption.

The first candidate uses built-in `omarchy.bar` on actual x86_64 Omarchy. Qualify v4.0.4 and the observed development revision separately if both will be claimed. A passing result for one does not confer rolling-release support for future Omarchy or Arch packages.

### Upgrade, backup, restore and removal

Package installation and user-state migration are different transactions. Pacman scripts do not mutate user work stores, enroll credentials or resume tasks. Stage verified package code, quiesce admission through the owning stack, inventory originals, perform owner-defined compatible migrations, activate a consistent version tuple, then start with diagnostics and reconciliation of any exposed owner state before enabling eligible new work. Keep a verified recovery package available. Fault injection must cover extraction, preflight, migration and activation; partial installation can legitimately leave the program unavailable, but never allowed to execute mixed code or reset uncertain state.

Use the native owners' backup and migration interfaces. The desktop does not introduce a parallel receipt journal or roll back authority state. A backup records public runtime identities, operator preferences, owner-consistent work/recovery stores, unresolved originals, receipt anchors and required separate secret custody. Do not copy live SQLite files without the owning snapshot contract. Restore stages privately, validates archive paths/hashes/ABIs and reconciles against current authority and external effects before any new execution. An older backup is not proof that later effects never happened.

Omarchy root snapshots leave `/home` and `~/.config` unchanged. After root rollback, an older native package may encounter newer plugin and owner state. Refuse incompatible writes and retain a compatible read-only recovery path where the owner supplies one. Never reverse receipt anchors, reservations, revocation or original-operation knowledge to make an older binary start. [Pinned snapshot contract](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/manual/47-system-snapshots.md)

Plugin disable/removal disconnects presentation. Backend removal first reports running/unresolved work, performs qualified bounded stop and preserves owner state, receipts, project artifacts, backups and recovery requirements. Remove only package-owned files and explicitly opted-in registration keys. Purge is a separate deliberate destructive workflow under the owning decommission contract; unresolved custody prevents automatic purge. ENOSPC, inode exhaustion, EIO, read-only state and missing recovery packages must produce explicit refusal without deleting history.

Security updates identify affected exact tuples and invalidate new admissions as appropriate. Replacement signatures, provenance and qualification must pass before activation. An advisory is not authority to resume a task, change provider/recipe or broaden a grant.

## Diagnostics, privacy and acceptance

Show component-specific failures: plugin/client mismatch, controller unavailable, native owner offline, stale event stream, session/lock uncertainty, credential store unavailable, host/backend mismatch, missing host qualification and unresolved work. Include observation time and profile identity. Prefer shared subscriptions and owner-approved diagnostics. Do not repeatedly poll recovery inspection to render a spinner; the recovery owner identifies settlement-reserve harm from that pattern.

Operational logs contain fixed codes, bounded counters and redacted identifiers. Prompts, source, provider credentials, approval bodies, raw paths, clipboard, window titles and core dumps are excluded by default. Local diagnostic export has an explicit size cap, contents preview and omission marker; sharing is a separate action. Receipts and original-operation fences remain under their owner retention policy and are not pruned with diagnostic logs. Storage pressure stops new effects before authoritative persistence becomes unavailable.

The shared qualification contract owns evidence format and verdicts. This annex adds platform cases, not fixture schemas or a second validator. Each case records trigger, independently observed result, exact tuple, owning gate, logs/artifact digests and negative controls. Unknown, refused, skipped and passed remain distinct. Required unexecuted cases leave the profile unqualified.

| Case group | Required trigger and independent oracle |
| --- | --- |
| Shell lifecycle | Late injection, 20 widgets across monitors, reload while a command result is lost, plugin disable and replacement bar; process/socket census proves one client and no duplicate work. |
| Rendering/privacy | Real keyboard/IME/AT-SPI, themes, large text, lock/unknown-lock, persisted notification clicks and DND; rendered observations plus canary scans verify usable controls and minimal content. |
| Peer and session boundaries | Wrong UID/process/session, stale socket, guest attempt to reach operator socket, logout with linger, suspend/resume and missed events; owner peer-auth tests and external effect counters verify refusal. |
| Observe source independence | Qualify receipt/hook observation with W1/recovery owners and their read/event adapters absent; independent request/subscription traces show no access to them, optional views remain unavailable, and useful receipt/hook reads and resynchronization succeed. |
| Installed CLI consumer | Invoke the packaged `chio` operator client under standard-user enrollment, consuming shared packet 4a's source and installed suites. Useful baseline Observe and cross-client read agreement succeed without execution owners; auth/tuple/reply/terminal-input negatives, interrupted pipes, update/logout and reconnect preserve native authority. For each exposed mutation, CLI/workbench concurrent original-ID and lost-reply tests show one original outcome/uncertainty and no duplicate downstream effects. Bind evidence to the actual CLI/controller/protocol tuple; missing CLI acceptance cannot satisfy program completion or CLI-support claims. |
| Execution deadline and authority expiry | In actual owner suites and on the installed host, pair useful unexpired execution with suspend past local deadline and absolute expiry in separate cases (the other bound remains valid), realtime forward/backward jumps across expiry, and restart/changed or uncertain boot-clock basis. Independent native dispatch/effect counters and process/cgroup custody observations prove the native fence precedes untrusted continuation on resume, no new protected dispatch/continuation after expiry, no clock-induced renewal, and bounded closure or retained unresolved custody. UI countdown/disabled controls are not an oracle; previously admitted external effects remain separately reconciled. These execution cases do not gate basic Observe. |
| Backend and custody | Exact Pi/bubblewrap and mini-swe/rootless-engine positive task, filesystem/network/FD/process negatives, engine-socket/group denial, double-fork and detached descendants; S7 owner verification and outside-guest sentinels/census establish effects and absence, including after runner/daemon crash. Any opted-in rootful profile repeats qualification independently. |
| Engine privilege and limits | Rootless endpoint/config/UID-map drift, substituted rootful socket, missing user namespaces or cgroup delegation, CPU/memory/PID pressure and stop under pressure; independent host credentials, namespace maps, cgroup counters/effective limits and descendant census establish confinement, enforcement and custody. Lost rootless support refuses before work without a rootful retry. |
| Storage and output limits | Silent volume/layer/temp/cache byte and inode exhaustion, stdout/stderr floods separately and together, stalled consumers, outside-container engine-log growth and concurrent tasks; independently measured host quotas/usage and every output/log sink prove per-task and aggregate bounds, admission refusal and retained receipt/controller/stop headroom. Missing limits refuse before dispatch; cleanup failure retains unresolved custody. |
| Work and recovery | One W1 request, fixed recipe, review artifact, unknown post-effect reply, crash and reconnect, repeated stop; owner receipts/work/recovery views and an external mutation counter establish no substituted/repeated effect. |
| Approval/publication | Direct installed Pi utility denial, wrong approval ID/decision/request/subject/expiry, missing S28 or production verifier, stale review digest/destination; no credential retention or dispatch in negatives. |
| Host launch | Each of six selected hosts, exact version and I01-I08 record, unsupported default, removed adapter and bypass attempts; native operation counter and outside-guest route probes determine the claim. A fully qualified protected candidate still refuses production activation/promotion without the first sealed W1 release record; sealed promotion succeeds independently of O5. |
| Distribution | Public-only clean install, plugin-only, default-branch drift, altered QML, absent locked commit, unsigned/revoked package, dependency/PATH drift; independent retrieval/hash/signature checks plus actual launcher behavior. |
| Recovery operations | Upgrade interruption, incompatible rollback, root snapshot with newer home, old/corrupt backup, ENOSPC/EIO, uninstall with unknown effect; owner anchors, effect counter and file/package inventory verify custody preservation. |

Compositor mutations, configuration repair and delegated execution do not appear as optional hidden release gates. They are outside this platform delivery. Extending the program requires changing the owning design and qualification, not enabling an extra desktop tool.
