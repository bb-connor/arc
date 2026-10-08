# Linux native host and Omarchy platform annex

Status: accepted platform direction under [ADR-0038](../../../adr/ADR-0038-desktop-operator-program.md), amended for native host integration. Implementation and installed qualification remain open. Confidence: high in ownership and source findings; moderate in platform feasibility; unknown for the complete installed composition.

Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries. This annex delivers reusable Linux host bindings and native services for existing harnesses, applications and Herdr. The Omarchy shell and browser workbench are optional consumers. A Linux host must install and perform every advertised systems capability with all Chio graphical clients absent.

The [native host contract](../2026-10-07-desktop-integration/HOST-CONTRACT.md) governs the direction. Read [consumer acceptance](../2026-10-07-desktop-integration/CONSUMERS.md), the [program map](../../../architecture/PROGRAM-MAP.md), [qualification contract](../2026-10-07-desktop-integration/QUALIFICATION.md), optional [operator projection](../2026-10-07-desktop-integration/OPERATOR.md), [implementation packets](../../plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md) and dated [native Linux research](research/native-host-services.md). S4, S5, S7, S8, S28, W1 and doc 19 identify existing owners, not new platform APIs. No installer, package, service or supported runtime is delivered by these documents.

## Product and boundary scope

| Surface/profile | `boundary_class` | `planning_status` | Admission and claim boundary |
| --- | --- | --- | --- |
| Native host API/binding and CLI diagnostics | `advisory_only` | `ready_after_adr` | Installed authenticated owner reads and truthful compatibility/provenance; no frontend or execution-owner prerequisite for basic Observe. |
| Hook-mode host observation | `detect_only` | `ready_after_adr` | Actual host/plugin provenance and observation gaps. Hook absence, timeout or crash can leave a tool running. |
| Governed work/resource coordination | `prevent` | `ready_after_adr` | Landed native work/process/resource owners and their exact acceptance, accessed through supported harness/application bindings. Sharing and cross-organization claims add their own CONSUMERS and owner gates. |
| Sealed W1 coding workload | `prevent` | `ready_after_adr` | One conformance workload using existing runner/resource owners, fixed recipe/acceptance, S7 and current host gates. It is not the product definition or a prerequisite release for other hosts. |
| Native approval and per-task closure | `prevent` | `ready_after_adr` | Owner-provided pre-effect decisions and S4 closure; attributable approval requires S28, a production passkey verifier and installed Pi utility repair wherever consumed. |
| Protected interactive host | `prevent` | `ready_after_adr` | Doc 19 protected mode removes native-shell bypass; each selected host independently requires its exact installed I01-I08 and native/profile release acceptance. |
| Boundary interactive: gateway-routed calls | `prevent` | `deferred` | Only calls actually authorized before dispatch qualify; denying bypass routes and containing descendants require independent evidence. |
| Boundary interactive: shell/workspace interior | `cannot_see` | `deferred` | Native-shell writes inside its sandbox have no per-write Chio decision or receipt. |
| Optional Omarchy/QML or workbench consumer | `advisory_only` | `ready_after_adr` | Status, navigation and separately gated actions; no issuer, work owner or mandatory native service. |
| Arbitrary desktop/compositor control and configuration repair | `cannot_see` | `hard_skip` | Removed from this integration program. |
| Native scoped delegation and descendant custody | `prevent` | `ready_after_adr` | Existing authority/process/budget owners qualify the actual serving route, supported depth and allocation form, narrowing, ancestor revocation and descendant custody through C10/Q25. Missing owner source/evidence leaves that capability unavailable; no platform child runner or authority. |
| Cross-host custody transfer and live migration | `prevent` | `deferred` | Separate native owner contracts and fencing/recovery evidence are required. Local delegation or an organizational exchange does not establish custody transfer, migration or globally atomic accounting. |

`planning_status` follows [ADR-0011](../../../adr/ADR-0011-boundary-taxonomy-product-wording.md). `ready_after_adr` permits planning, not execution or a runtime claim. Candidate delivery, source qualification, installed execution and supported release promotion remain distinct.

The complete host program retains Claude Code, Codex, Cursor, Hermes, Pi and OpenClaw. Each adapter qualifies independently; no all-six gate blocks an otherwise qualified selected host, and no Pi result qualifies another. Pi's recorded restricted-session evidence makes it a useful candidate, not the mandatory first product. Historical plugin 0.1.0/Pi 0.85.1 results do not qualify the newer tuple or Omarchy.

Applications own task planning, assignment, editing and review UX. Native owners retain work commitments, resource identity/generation, authority, aggregate capacity, disclosure, evidence and original-operation recovery. Execute CONSUMERS coordination and shared-resource cases through real native bindings, then cross-organization cases through independently enrolled peers and local policies when those owner gates are delivered. A process exit, recipe pass, accepted result, settlement and bilateral delivery remain different facts. Editing or publishing a developer checkout is a separately authorized owner operation.

Each profile advances from implemented owner composition through O6 public candidate and O7 installed acceptance independently. Sealed W1 coding supplies an exact useful workload and its applicable native cases; protected hosts do not require a prior sealed-coding release. Observe, approval, stop, native coordination and selected host support each carry only their own required gates. Optional graphical consumers never gate native package installation or a headless release.

## Architecture and ownership

Reuse supported native kernel/process/work/recovery bindings and their hosted services. This is not a universal daemon requirement: a trusted embedding and a separately hosted process/control/resource service retain their declared owners and TCB. Linux supplies peer identity, service lifecycle, process/cgroup/namespace enforcement, credentials and I/O adapters. It introduces no second scheduler, task journal, authority store, peer-auth stack or sandbox runner.

The proposed C-layer controller and `chio.operator.v1` may compose operator views for CLI, workbench, Omarchy and macOS clients. That optional controller stays outside the TCB and owns no signing keys, authority store, approval issuer, trusted fact assertions or independent execution journal. It is not the kernel ABI or prerequisite for direct supported owner bindings. Applications such as Herdr and Megastart consume existing owner contracts; their app/demo endpoints do not become a universal native ABI.

### Native deployment and enrollment profiles

| Profile | Linux lifecycle and authority contract |
| --- | --- |
| User-session host | One explicitly enrolled graphical login session per UID, bound to native-verified UID, boot/logind identity and host/client incarnation. It runs without a Chio GUI but retains session lock/logout fences. |
| Service host | A separately enrolled service principal with installation/host identity, finite scopes/expiry, operator authorization, credential custody, durable state and boot/restart reconciliation. Login-independent continuation requires this owner's explicit grant and policy. |
| Embedded host | An application embeds the kernel at a declared trusted boundary and qualifies each consumed native port. An embedding is not proof of OS confinement or public service readiness. |
| Optional presentation | QML, workbench or other clients connect with independently scoped identities. Closing/removing them cannot delete custody, renew capacity or resume an original operation. |

For the user-session profile, a per-user systemd manager or socket is not proof of a login session. Refuse a second concurrent session even for the same UID; no reassignment after logout/restart. Lingering cannot preserve human session authority. Lock, logout, unknown liveness and missed observations fence affected disclosures/actions. Closure is restricted to original owner references bound to that session, never another session or service profile. Session replacement requires explicit enrollment and original-custody reconciliation. Multiple independent sessions require later qualification.

For the service profile, use a separately provisioned unprivileged service identity and native enrollment, not inferred permission from root, UID equality, detached launch or linger. Qualify startup without a graphical login or unlocked desktop credential store, secret rotation/revocation, lease expiry, duplicate instances, interrupted enrollment, boot changes, shutdown and decommission. Credential unavailability refuses through the existing broker; no plaintext or personal-session fallback. Enabling a user manager at boot may be an explicit service-profile provisioning choice, but never an implicit desktop install action. Until these owner artifacts exist, login-independent operation remains unavailable.

The inspected secure IPC owner authenticates one exact expected PID/UID/GID; a general multi-client service needs an owner extension for enrollment, retained process-instance identity and authorization. User-manager/DBus-launched clients may have no direct logind session. Race-prone PID/`/proc` lookups or `XDG_SESSION_ID` cannot fill the gap. Preserve secure socket custody, prove endpoint/client identity and qualify inherited/transferred FDs, PID reuse and client replacement. See [verified source and upstream constraints](research/native-host-services.md).

| Linux integration need | Existing owner and required reuse |
| --- | --- |
| Tasks, requests, acceptance, resources and projections | W1 landed preparation/command/query contracts and resource owners; client-owned task/worktree/review UX. |
| Original-operation lookup and recovery | Recovery `InspectWorkflow`, `SubmitApproval`, `ResumeWorkflow`, `CancelWorkflow`, W1 queries and S9 M20 retry classes. Unknown effects never become fresh operations automatically. |
| Event delivery | S5 Part B for exposed subscriptions; Part A transport fixes precede them. Basic Observe uses selected authenticated sources. No platform polling loop over `InspectWorkflow`; direct owner bindings consume their own supported contracts. |
| One-task stop | S4 phases 1 and 2 closure with actual result kinds; previously admitted effects can remain unresolved. |
| Durable emergency stop | S8 phase 1 supplies durable `Kernel` stop and S30 routes/results; `Tenant` and `Recovery` wait for phases 4/5. Never infer global stop from logout. |
| Identity and approvals | Native enrollment/authority owners; human attribution adds S8 S28 phase 3 production roster and passkey verification. `SharedCredential` remains labeled as such. |
| Local peer authentication | `chio-secure-ipc` Linux `SO_PEERCRED` and socket custody, extended and qualified for selected clients/profile; no second shim authenticator. |
| Process custody and termination | `chio-process`/`ProcessRegistry` plus existing host lifecycle; systemd/cgroups enforce host lifetime and resources, not semantic work identity. |
| Credentials and provider access | Existing secret broker/model relay; separately qualified service credential custody where required. |
| Sealed coding conformance | `chio-mini-swe`, restricted Pi/coding resource and owner-supported intake/review interfaces through the selected CLI/application. Rootless support requires runner changes and qualification. |
| Isolation evidence | S7 and thin backend adapters. Isolation denies access; Chio grants operations through native resources/gateway/relay. |
| Shared resources and organizational crossings | Existing capacity/work/resource/federation/disclosure owners and CONSUMERS evidence. Linux UID maps/cgroups are not organizational authority or globally atomic budgets. |

Bind exact available sources and acceptance before consuming APIs. Basic receipt/hook Observe must work with W1/recovery/execution owners absent, with no reads/subscriptions to them. Selected work/recovery, approval, stop, execution, sharing and organizational crossing functions add only their own owner gates. S3/S4/S7/S8/S9/S10 and S5 are consumed where mapped; NK-01 to NK-03 or S11 are not blanket dependencies for simple supported reads. Native claims retain their actual current invariants regardless of client.

### Linux backend composition

Use the Pi restricted bubblewrap profile as the initial agent-host candidate and reuse the Docker-based `chio-mini-swe` path for the sealed workspace. The default qualification candidate is **rootless Docker**, retaining the existing runner's exact CLI/API contract where it proves compatible. The inspected mini-swe source explicitly rejects `name=rootless`/`name=userns` and fixes `/var/run/docker.sock`; supporting this candidate requires an existing-runner owner change before qualification. Retain current protections while adding exact endpoint/configuration, mapped ownership, volume, stream and lifecycle support. No inspected result establishes rootless qualification. Run its real source/edit/test/artifact flow and independent confinement, custody and resource checks on the selected Linux x86_64 installation, with a separately measured Omarchy tuple before claiming Omarchy support. Missing rootless prerequisites, incompatible runner behavior or ineffective limits make the profile unavailable; there is no fallback to rootful Docker, sudo or an unrestricted process.

Both pinned Omarchy revisions install Docker and enable its system socket, but explicitly withhold default docker-group membership; Sudoless Docker is a separate opt-in. Existing installations must be measured. Access to the rootful daemon through the `docker` group is root-equivalent. If supported at all, that path requires a separately selected, explicitly documented privileged profile whose trusted host-side runner and root daemon are in the containment TCB. A non-root CLI UID or `userns-remap` does not make that daemon rootless. This changes the trusted host exposure, not Chio's authority owner: kernel/work/resource owners still grant operations; neither engine, controller nor QML becomes an issuer. [Pinned Omarchy posture and engine research](research/linux-platform.md#container-engine-privilege-and-compatibility)

Rootless Podman is a separate candidate, not a drop-in alias. Inventory the runner's actual CLI/API, archive/copy, exec, exit/stream, image, mount/UID-map, network, stop/remove and custody requirements, then qualify the selected Podman version against them. Its Docker API compatibility layer alone proves no runner equivalence. Any necessary adaptation belongs to the existing runner/backend owner. An engine change creates a new qualification tuple.

Only the qualified trusted host-side runner may access the selected engine endpoint. Agent guests and test recipes receive neither engine sockets (including rootless sockets), API credentials, inherited connected FDs nor docker-group privileges. Strip inherited privileged group access and verify the resulting credentials; socket omission alone is insufficient. Bind the runner to the measured local endpoint and effective configuration; ambient Docker contexts, `DOCKER_HOST`/`DOCKER_CONTEXT`, user config or a substituted socket must not redirect it. Rootless engine access still permits powerful actions as its host user and is not a boundary against malicious trusted same-user desktop software. Inventory any coexisting rootful daemon and prove that the Chio runner and guests cannot reach it under the rootless profile. Installation does not silently change upstream group membership, disable unrelated Docker workloads or enable lingering.

Before admission, the runner/resource owners enforce finite per-task and aggregate budgets for writable volume/layer bytes, temporary/cache data, inodes, stdout/stderr ingress and buffering, retained output and engine logs. Inventory the actual host storage and sinks, including Docker daemon/container logs, journals and spool files outside container filesystems. A read-only container root, tmpfs byte cap or client output cutoff alone cannot qualify those other surfaces. Map concrete quota, output and admission APIs through O0; missing enforceable bounds make the profile unavailable. Reserve sufficient host capacity for receipts, original-operation state, stop/recovery and the controller under concurrent tasks. Independent host quota/usage and sink measurements must prove the configured limits and headroom. Silent disk/inode exhaustion, separate and combined stdout/stderr floods, stalled consumers and concurrent-task pressure must refuse new admission or stop affected execution before that reserve is consumed. Cleanup must remain bounded and independently observed; unresolved resources retain custody, and authoritative evidence is never deleted to make room or replaced by a false successful result.

The S7 owner must add or qualify the `AgentHostBwrap` evidence kind before any consumer asserts that claim; `ProcessContainer` covers a qualified container backend. OpenShell is a later external-runtime adapter once its contract and evidence are stable. Missing/unknown backend evidence renders the owner-defined unconfined/unavailable state. QML and the controller cannot mint evidence or infer confinement from a process name, successful launch or manifest.

`chio-cage` remains a specific tool-server profile. Its inspected x86_64, Landlock and syscall constraints do not run Node/Pi; this program neither forces Node into it nor relaxes its policy. A tool-server cage receipt is not evidence for the whole agent. Preserve separate inventories for agent, trusted resource and test recipe, including exact runtime/loader files, mounts, descriptors, namespace behavior and effective filters. The historical privileged ARM64 bubblewrap run is research evidence, not native Omarchy acceptance.

Agent access is limited to the qualified gateway/model-relay descriptors and selected workspace/runtime closure. No operator endpoint, provider secret, authority store, SSH agent, desktop bus, compositor socket or container-engine socket crosses into the agent. Measure filesystem, raw network, inherited descriptors and subprocess escape attempts from outside the guest. A hook plugin cannot close these routes.

Test harness cleanup belongs to the shared Linux qualification/process tooling. Preserve the Linux child-subreaper lesson: a dedicated fixture worker establishes and verifies child-subreaper custody before starting hostile descendants, remains alive during bounded cleanup, and reports unavailable custody as a prerequisite refusal. It must not silently change the controller or shared orchestrator's subreaper state. Exercise double-fork, process-group escape, detached descendants, full stdout/stderr pipes, timeout, stop escalation and orphan reaping. Independent process/cgroup observations must establish absence; worker exit or a returned timeout is insufficient. Failed cleanup retains unresolved custody and fails the case. This acceptance requirement does not authorize another Omarchy-private process runner.

## Optional Omarchy shell contract

The optional native shell consumer is a thin plugin with ID `computer.chio.desktop`, `bar-widget`, `panel` and `service` kinds and `keepLoaded: false`. It shows receipt/hook status, boundary labels, connection state and navigation to an explicitly selected compatible application or diagnostic view. Task/recovery counts and hints appear only when their separately qualified owner views are exposed. The selected application owns task creation, project intake, editing and full patch review; native resource owners retain capture/publication semantics. Workbench is one optional client. Small QML approval/stop affordances may be added only after the shared native paths qualify; they consume the same native authority as other clients and add no task editor or required browser dependency.

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

QML stores visual preferences only. Native owners retain durable work, original-operation and artifact state. Clear sensitive in-memory details on lock, unknown lock state and relevant disconnects. A fixed opener accepts only allowlisted views and owner IDs and cannot authorize, resume, publish or open task-supplied executable content. No plugin self-installation, package-manager invocation or unattended secret import is permitted.

### Launch paths and the six hosts

The upstream launcher uses hardcoded agent cases. Its auto-approved modes, including permission-skipping flags where present, are not Chio protection. Upstream Agents usage/subscription UI remains useful and independent of Chio authority. Do not shadow `pi`, replace `omarchy-agent`, change the selected default agent or edit upstream aliases and bindings.

If the desktop consumer is selected, provide a package-owned desktop/Walker entry and optional owned menu action, **Launch default agent in protected mode**. This is an opt-in Chio entry, not a modification of the upstream launcher. Resolve the user's selected host through the inspected platform adapter, display it, then require a matching doc 19 I01-I08 acceptance tuple for that host/version/plugin/backend. Production activation requires that protected tuple's own O7/native acceptance and promotion; no prior sealed-coding release is required. Unsupported selections explain why and offer an explicitly chosen qualified host; they never silently launch the native auto mode. Host identity and qualification are rechecked at launch. Until the entry qualifies, retain accurate unavailable status and any independently qualified native diagnostic/application navigation. No workbench install is required.

Install menu customization only through explicit onboarding using one owned static key and a literal opener. Preserve unrelated user JSONC, comments and shortcuts. Unsupported syntax produces a proposed edit and leaves the file untouched. Walker/desktop visibility and the menu guard are convenience, not authorization. Existing keyboard shortcuts remain the user's; a custom shortcut requires an explicit choice and collision check.

## Session, service and operational lifecycle

Package selected native owner services and Linux adapters with role-specific systemd integration; package the optional projection controller only when consumed. Installation places inert units; activation requires the selected profile's native enrollment. User-session onboarding never enables lingering, imports the full user environment or creates a root controller. Verify actual graphical-session/logind behavior, including pre-existing linger. Service-profile provisioning separately records its boot/user-manager policy and service credentials. Rootless Docker uses its supported user-service arrangement; a system-wide Docker unit with `User=` is not an equivalent supported deployment. Keep one cgroup writer per delegated subtree and measure actual delegated controllers; systemd/engine availability grants no Chio authority.

| Transition | Required owner interaction and observable result |
| --- | --- |
| Plugin load, unload, reload or theme change | Presentation connects/disconnects only; native work identity survives and no task, approval or stop is synthesized. |
| Controller crash/restart | Reconnect through shared transport, reload native projections and unresolved originals; no automatic new work or replay. Native custody is owned by `chio-process`. |
| User-session lock or unknown lock state | Conceal sensitive UI and disable new operator mutations; admitted work may continue only within its existing expiry/scope and selected qualified policy. |
| User-session unlock | Fresh identity/session, compatibility and owner snapshot; no extension of approval/capability expiry. |
| Suspend/resume or clock uncertainty | Host adapter invalidates stale observations; each selected native owner revalidates its actual read/action/credential/lease authority and freshness under Q31 before further protected access. Execution additionally enforces the boot-associated `CLOCK_BOOTTIME` task deadline and authority-issued absolute expiry. Resume, realtime rollback or restart cannot revive expired authority, renew a grant or replay work. |
| User-session logout/session loss | Stop new admission and use S4/process custody for bounded local termination, retaining unresolved effects. Must hold with lingering enabled and missed events. |
| Per-task stop | Invoke S4 closure, render actual result and independently verify descendant termination where claimed. Do not imply an external effect was undone. |
| Broad emergency action | Use S8 phase 1 for `Kernel`; later `Tenant`/`Recovery` scopes require phases 4/5. Preserve the distinction from one-task closure and the current unqualified process-local implementation. |
| Service boot/restart or lease revocation | Verify service enrollment, installation/boot identity, credentials and original custody before new admission; unchanged grants are not renewed. Revoked/expired/unprovable authority refuses and follows scoped owner closure. |
| Credential store lock/removal | Broker and relay refuse affected new access; preserve unresolved operations and receipts. No plaintext fallback. |

Keep controller, trusted relay/launcher and guest/resource units separately scoped where required by their existing owners. Use role-specific tested hardening, bounded restart/stop behavior, restrictive umask, core-dump suppression, measured cgroup resource limits and fixed executable paths. A unit option unsupported in the user manager must not become silent partial protection. Hardening that disables namespaces or required Node threads cannot be fixed by removing all confinement. A systemd analyzer score is supplementary evidence; effective kernel properties and negative probes decide acceptance.

Every selected time-bounded capability maps to shared Q31 through its actual
native owner, including protected reads/subscriptions, snapshot freshness,
approval/challenge credentials and service leases where exposed. O0 records the
actual clock/freshness APIs, validity bounds, retained expiry decision, validation
points and persistence/restart/boot reconciliation; do not substitute a desktop
timer or infer this contract from a task deadline. Useful unexpired reads,
approvals and service access are positive controls. Expire each authority before
rolling realtime back into its former validity window; separately exercise
forward jumps, suspend across expiry, restart/boot changes and missing or
uncertain clock/freshness evidence. Native owners must retain the expired state
or refuse when its basis is unprovable, never revive the old grant. Independently
probe protected read bytes, downstream effects and credential issuance/storage/
reuse as applicable. A stale approval cannot yield an accepted credential or
effect, and a stale service lease cannot authorize reads or actions. These gates
apply without execution owners; Observe consumes its own Q31 read/freshness
cases, not Q12/Q19 task-lifetime cases. Already disclosed bytes or completed
external effects are not claimed to be undone by expiry. Missing enforcement
keeps the dependent capability unavailable.

Separately, the existing authority/work/runner/process owners must define and qualify the
actual Linux clock contract before an execution profile is enabled. The inspected
mini-swe transport uses `time.monotonic()`; this source does not establish the
suspend-inclusive contract below. The owner must supply the complete native path. Bind local
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
observation still qualifies its own Q31 read authority and freshness. This carries
the [Linux clock research](research/linux-platform.md#upstream-linux-conclusions)
into a required implementation and installed-qualification contract.

Bound each stop and cleanup phase with an explicit selected-profile deadline. If complete process absence or original outcome cannot be established, render the owner's unresolved state and preserve recovery custody. Neither SIGKILL nor a clean systemd state proves absence of a remote effect.

## Packaging, compatibility and distribution

Delivery roles are separate: native owner dependencies and CLI, portable Linux host adapters/units and profile configuration, optional application/harness adapters, and optional Omarchy shim/opener/desktop registration/QML plugin. The proposed projection controller is packaged only for consumers that need it. Native package installation has no workbench/Qt/Quickshell/Hyprland dependency. Final Arch package names are a packaging decision, not available product commands. Use pacman-compatible signed artifacts with fixed public source inputs, package hashes, dependency/runtime inventory, license/SBOM provenance and build records. Never resolve the protected runtime through `mise`, ambient `PATH` or an unrecorded developer checkout.

The native package/dependency inventory includes the existing `chio` CLI and
selected supported native bindings, with exact executable/source identities and
owner/protocol pairing through shared packet 4a. Optional operator view
composition separately adds its controller/common-protocol tuple and
selected-surface acceptance. An unqualified candidate may be assembled
and published before final CLI acceptance. Program completion and CLI-support
claims require source and installed-client evidence; a platform opener or protocol
probe does not deliver the promised CLI. Useful baseline Observe must work without
absent W1/recovery/execution owners, and selected actions add only their own gates.

The support record binds one explicit profile to the following tuple:

- Public Chio owner sources and exact selected native/binding/bridge binaries, plus optional controller/operator binaries when consumed; work/operator/state ABIs and acceptance records.
- Linux distribution/systemd, architecture, kernel and effective namespace/cgroup/LSM probes; Omarchy revision and Quickshell/Qt/Hyprland only for a selected Omarchy consumer.
- Each selected client/binding/protocol identity; optional plugin commit/full file inventory and shell features only when that consumer is claimed.
- Agent/plugin/runtime lock, backend/image/runtime closure, gateway/resources, policy, fixed recipe and verification identities.
- Engine/CLI/API and container runtime identities, runner binary/launch identity, daemon rootless/rootful mode, host UID/GID/supplementary groups and measured user-namespace UID/GID maps; subordinate-ID ranges and mapping-helper identities.
- Engine socket endpoint/ownership and effective client/daemon configuration digests, service units/overrides, storage/network/rootless-helper identities, mounts and image digest. Required cgroup v2 controllers/delegation and observed limits are bound to this same profile, not inferred from accepted flags.
- Finite per-task and aggregate writable-byte/inode quotas and output ingress/buffer/retention limits, actual host storage and engine-log sinks, native enforcement identities, admission reservations and independently measured receipt/controller/stop headroom.
- Provider/model route and account binding, supported enforceable limits and unavailable dimensions; credential custody profile.
- Native deployment profile, enrollment/principal and credential context, adapter and effective units/overrides; user-session lock/logout/linger behavior or separately qualified service boot/lease/revocation behavior.
- For every selected time-bounded capability, its Q31 native owner, actual clock/freshness API and validity semantics, retained expiry and restart/boot reconciliation, plus independent protected-read/effect/credential evidence. Read, approval and service authority do not inherit an execution deadline implementation by implication.
- For execution profiles, the actual native clock/deadline implementation, boot-identity binding, suspend-inclusive local lifetime, authority absolute-expiry checks and restart/clock-uncertainty reconciliation evidence.

Source presence, historical tests, a valid manifest and package signatures are separate facts from a supported tuple. The read-only diagnostics path may operate on an unknown tuple if its own transport is compatible; affected execution stays unavailable. Report the changed dimension instead of turning a healthy daemon into an execution-ready claim.

Omarchy's post-update hook can invalidate compatibility, but it runs before later runtime updates and cannot certify final compatibility. Remeasure at startup, reconnect and admission using the shared integrity gates. An updated native library, unit override or kernel invalidates the dependent profile until revalidated. Modified QML invalidates its optional consumer acceptance, not an unrelated qualified native path. Bind dependencies explicitly so a plugin/workbench update cannot become a blanket headless outage. Ordinary host security updates need not be blocked to preserve Chio availability.

### Public candidate installation and promotion

Publish independently retrievable, explicitly **unqualified qualification candidates** before the clean-install campaign; supported release promotion follows that campaign. O7 promotes each selected native, workload and harness profile against its own installed acceptance. Protected-host promotion does not require a prior sealed W1 coding release; candidate publication alone satisfies no acceptance gate. Observe, approval and stop can qualify and promote independently. The release record must contain real public URLs and revisions before commands are generated. These documents intentionally provide no invented plugin repository or native package URL.

The inspected `omarchy plugin add` accepts a repository URL and `--yes`, not a revision selector. `--yes` without `--enable` installs disabled. For the optional plugin only, the clean-host procedure is:

1. Verify the signed public candidate lock and obtain its repository URL, full delivery commit and independent file inventory. Confirm that the plugin ID/directory and persisted enablement do not already exist.
2. Run `omarchy plugin add "$plugin_repository_url" --yes` with values from that verified lock. Do not pass `--enable`.
3. Select the exact public commit using `git -C "$plugin_install_dir" checkout --detach "$plugin_public_revision"`. Verify HEAD, the expected ID, all file paths/modes/digests (excluding Git metadata), absence of unexpected files, compatible native/plugin pair and disabled state. A clean Git status alone proves none of these identities.
4. Run `omarchy plugin validate "$plugin_install_dir"` for the selected installed Omarchy. Only then explicitly run `omarchy plugin enable computer.chio.desktop`.
5. Observe real shell loading and native connectivity. Plugin installation/enablement does not install the backend, create credentials or start an agent. Repeat plugin-only/missing-backend and incompatibility cases independently.

The pinned [release add](https://github.com/omacom/omarchy/blob/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/bin/omarchy-plugin-add), [development add](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-plugin-add) and [enable](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-plugin-enable) sources define that interface. Recheck installed behavior before delivery. Do not invent `--ref`, `--revision`, archive-install flags or a Chio permission field in the Omarchy manifest. Upstream update can change the Git plugin independently; changed content requires verification/activation again and may refuse on a detached checkout. It never preserves qualification by assumption.

A selected Omarchy shell candidate uses built-in `omarchy.bar` on actual x86_64 Omarchy. Native Linux support qualifies without that shell. Qualify v4.0.4 and the observed development revision separately if both will be claimed. A passing result for one does not confer rolling-release support for future Omarchy or Arch packages.

### Upgrade, backup, restore and removal

Package installation and user-state migration are different transactions. Pacman scripts do not mutate user work stores, enroll credentials or resume tasks. Stage verified package code, quiesce admission through the owning stack, inventory originals, perform owner-defined compatible migrations, activate a consistent version tuple, then start with diagnostics and reconciliation of any exposed owner state before enabling eligible new work. Keep a verified recovery package available. Fault injection must cover extraction, preflight, migration and activation; partial installation can legitimately leave the program unavailable, but never allowed to execute mixed code or reset uncertain state.

Use the native owners' backup and migration interfaces. The desktop does not introduce a parallel receipt journal or roll back authority state. A backup records public runtime identities, operator preferences, owner-consistent work/recovery stores, unresolved originals, receipt anchors and required separate secret custody. Do not copy live SQLite files without the owning snapshot contract. Restore stages privately, validates archive paths/hashes/ABIs and reconciles against current authority and external effects before any new execution. An older backup is not proof that later effects never happened.

Omarchy root snapshots leave `/home` and `~/.config` unchanged. After root rollback, an older native package may encounter newer plugin and owner state. Refuse incompatible writes and retain a compatible read-only recovery path where the owner supplies one. Never reverse receipt anchors, reservations, revocation or original-operation knowledge to make an older binary start. [Pinned snapshot contract](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/manual/47-system-snapshots.md)

Plugin disable/removal disconnects presentation. Backend removal first reports running/unresolved work, performs qualified bounded stop and preserves owner state, receipts, project artifacts, backups and recovery requirements. Remove only package-owned files and explicitly opted-in registration keys. Purge is a separate deliberate destructive workflow under the owning decommission contract; unresolved custody prevents automatic purge. ENOSPC, inode exhaustion, EIO, read-only state and missing recovery packages must produce explicit refusal without deleting history.

Security updates identify affected exact tuples and invalidate new admissions as appropriate. Replacement signatures, provenance and qualification must pass before activation. An advisory is not authority to resume a task, change provider/recipe or broaden a grant.

## Diagnostics, privacy and acceptance

Report component-specific failures through native diagnostics and selected clients: optional plugin/client mismatch or controller unavailable, native owner offline, stale event stream, session/lock uncertainty, credential store unavailable, host/backend mismatch, missing host qualification and unresolved work. Include observation time and profile identity. Prefer shared subscriptions and owner-approved diagnostics. Do not repeatedly poll recovery inspection to render a spinner; the recovery owner identifies settlement-reserve harm from that pattern.

Operational logs contain fixed codes, bounded counters and redacted identifiers. Prompts, source, provider credentials, approval bodies, raw paths, clipboard, window titles and core dumps are excluded by default. Local diagnostic export has an explicit size cap, contents preview and omission marker; sharing is a separate action. Receipts and original-operation fences remain under their owner retention policy and are not pruned with diagnostic logs. Storage pressure stops new effects before authoritative persistence becomes unavailable.

The shared qualification contract owns evidence format and verdicts. Map selected Q23-Q31 and CONSUMERS C01-C11 explicitly: Q23/C01-C02-C05 for independent native consumers, Q24/C09 for advertised or peer-policy-selected passports, Q25/C10 for native delegation, Q26/C11 for swarm/accepted-dependency behavior, Q27/C03-C04 for shared resources, Q28/C06-C07 for independent organizational cooperation, Q29-Q30 for native profile/owner closure, and Q31 for every selected time-bounded capability, including read/approval/service authority. C08 applies to selected acceptance/release. Unexposed features remain unavailable and do not become baseline prerequisites. Native profile cases apply without a GUI. Shell/browser/accessibility cases apply only to their selected consumer; removing that consumer never removes a native obligation. This annex adds platform cases, not fixture schemas or a second validator. Each case records trigger, independently observed result, exact tuple, owning gate, logs/artifact digests and negative controls. Unknown, refused, skipped and passed remain distinct. Required unexecuted cases leave the profile unqualified.

| Case group | Required trigger and independent oracle |
| --- | --- |
| Optional shell lifecycle | Late injection, 20 widgets across monitors, reload while a command result is lost, plugin disable and replacement bar; process/socket census proves one client and no duplicate work. |
| Optional rendering/privacy | Real keyboard/IME/AT-SPI, themes, large text, lock/unknown-lock, persisted notification clicks and DND; rendered observations plus canary scans verify usable controls and minimal content. |
| Peer and session boundaries | Wrong UID/process/session/service principal, stale socket, guest attempt to reach operator socket, logout with linger, suspend/resume and missed events; owner peer-auth tests and external effect counters verify refusal. |
| Service-profile enrollment | Cold boot without login/key store, wrong/revoked service principal, UID/unit/process substitution, expired lease, duplicate instance, interrupted enrollment/rotation, boot change and loss of persistent custody; native dispatch/disclosure sentinels prove refusal and no takeover of session work. |
| Observe source independence | Qualify receipt/hook observation with W1/recovery owners and their read/event adapters absent; independent request/subscription traces show no access to them, optional views remain unavailable, and useful receipt/hook reads and resynchronization succeed. |
| Time-bounded authority in every selected profile (Q31) | Pair useful authorized protected reads, approvals and service access with expiry followed by realtime rollback into the old validity window, separate forward jumps, actual suspend across expiry, restart/boot changes and missing clock/freshness evidence. Exercise the actual native owner admission/revalidation paths on the installed host; retained expiry or an unprovable basis cannot revive the original read authority, approval/challenge credential or service lease. Independent protected-byte probes, downstream effect counters and credential issuance/storage/reuse observations show refusal without a new disclosure, effect or accepted credential as applicable. Map every exposed time-bounded capability to these cases and remove each required result from a passing manifest to verify affected activation/promotion refuses. A useful unexpired control must still succeed; UI state and source clock injection alone cannot qualify installed behavior. Observe requires its own Q31 cases without Q12/Q19 execution prerequisites. |
| Installed native API/CLI/harness consumers | Invoke the packaged `chio` client and selected supported bindings under the declared native enrollment profile, consuming their source and installed suites. Qualify CONSUMERS coordination, shared-resource and independent-organization cases when those capabilities are advertised, with every Chio GUI absent. Shared packet 4a qualifies the native CLI; optional operator projections add their own selected-surface suites. Useful baseline Observe and cross-client read agreement succeed without execution owners; auth/tuple/reply/terminal-input negatives, interrupted pipes, update/logout and reconnect preserve native authority. For each exposed mutation, independent-client concurrent original-ID and lost-reply tests show one original outcome/uncertainty and no duplicate downstream effects. Bind evidence to the actual CLI/native-owner/protocol tuple and any consumed controller; missing CLI acceptance cannot satisfy program completion or CLI-support claims. |
| Execution deadline and authority expiry | In actual owner suites and on the installed host, pair useful unexpired execution with suspend past local deadline and absolute expiry in separate cases (the other bound remains valid), realtime forward/backward jumps across expiry, and restart/changed or uncertain boot-clock basis. Independent native dispatch/effect counters and process/cgroup custody observations prove the native fence precedes untrusted continuation on resume, no new protected dispatch/continuation after expiry, no clock-induced renewal, and bounded closure or retained unresolved custody. UI countdown/disabled controls are not an oracle; previously admitted external effects remain separately reconciled. These execution cases do not gate basic Observe. |
| Backend and custody | Exact Pi/bubblewrap and mini-swe/rootless-engine positive task, filesystem/network/FD/process negatives, engine-socket/group denial, double-fork and detached descendants; S7 owner verification and outside-guest sentinels/census establish effects and absence, including after runner/daemon crash. Any opted-in rootful profile repeats qualification independently. |
| Engine privilege and limits | Rootless endpoint/config/UID-map drift, substituted rootful socket, missing user namespaces or cgroup delegation, CPU/memory/PID pressure and stop under pressure; independent host credentials, namespace maps, cgroup counters/effective limits and descendant census establish confinement, enforcement and custody. Lost rootless support refuses before work without a rootful retry. |
| Storage and output limits | Silent volume/layer/temp/cache byte and inode exhaustion, stdout/stderr floods separately and together, stalled consumers, outside-container engine-log growth and concurrent tasks; independently measured host quotas/usage and every output/log sink prove per-task and aggregate bounds, admission refusal and retained receipt/controller/stop headroom. Missing limits refuse before dispatch; cleanup failure retains unresolved custody. |
| Work and recovery | One W1 request, fixed recipe, review artifact, unknown post-effect reply, crash and reconnect, repeated stop; owner receipts/work/recovery views and an external mutation counter establish no substituted/repeated effect. |
| Approval/publication | Direct installed Pi utility denial, wrong approval ID/decision/request/subject/expiry, missing S28 or production verifier, stale review digest/destination; no credential retention or dispatch in negatives. |
| Host launch | Each of six selected hosts, exact version and I01-I08 record, unsupported default, removed adapter and bypass attempts; native operation counter and outside-guest route probes determine the claim. Each protected tuple promotes only after its own native/profile and installed I01-I08 evidence. Remove a required host case and activation/promotion must refuse; omit unrelated coding/GUI releases and an otherwise qualified host remains eligible. |
| Distribution | Public-only minimal Linux clean install with no Chio GUI, independently selected Omarchy/plugin installation, plugin-only, default-branch drift, altered QML, absent locked commit, unsigned/revoked package, dependency/PATH drift; independent retrieval/hash/signature checks plus actual launcher behavior. |
| Recovery operations | Upgrade interruption, incompatible rollback, root snapshot with newer home, old/corrupt backup, ENOSPC/EIO, uninstall with unknown effect; owner anchors, effect counter and file/package inventory verify custody preservation. |

Compositor mutations and configuration repair remain outside this delivery. Native delegation is part of the selected systems capability program and consumes C10/Q25 through its existing owners; it is not blanket-deferred. Cross-host custody transfer and live migration remain separate deferred extensions. Neither is an unrelated prerequisite for basic local reads. Coordination/shared-resource/organizational claims still require their explicit CONSUMERS and native-owner acceptance. Extending the program requires changing the owning design and qualification, not enabling an extra desktop tool.
