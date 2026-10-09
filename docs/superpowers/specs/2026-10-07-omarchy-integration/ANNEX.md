# Linux native host and Omarchy platform annex

Status: accepted platform direction under [ADR-0038](../../../adr/ADR-0038-native-host-program.md), reorganized on 2026-10-08 by the approved [north-star flows](../2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md). `planning_status: ready_after_adr` unless a row says otherwise; `boundary_class` is stated per operation. Status words follow the [status glossary](../2026-10-07-desktop-integration/STATUS-GLOSSARY.md). Nothing in this annex is implemented, installed, qualified or released.

**Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries.** This annex supplies the Linux services, custody, IPC, isolation evidence and packaging that the flows consume. Linux is the executing platform for HOST-M2 and HOST-M3 before the success test; macOS HOST-M2 comes after it (unified roadmap section 11). The Omarchy shell, workbench, notifications and Walker entries are optional consumers: every advertised capability installs and works with all Chio graphical clients absent.

This annex does not restate shared documents. Flows and owner changes are in NORTH-STAR-FLOWS; deployment profiles and the model-provider resource boundary are in [HOST-CONTRACT](../2026-10-07-desktop-integration/HOST-CONTRACT.md); every acceptance case is a row in [CASES](../2026-10-07-desktop-integration/CASES.md); harness scope is in [FIRST-CLASS-INTEGRATIONS](../2026-10-07-desktop-integration/FIRST-CLASS-INTEGRATIONS.md); owners and source pins are in [PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md). Work is sequenced in the [implementation plan](../../plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md). Dated source findings stay in [native Linux research](research/native-host-services.md) and [Linux platform research](research/linux-platform.md).

| Operation or surface | `boundary_class` | `planning_status` | Claim boundary |
| --- | --- | --- | --- |
| Native services, CLI and API diagnostics | `advisory_only` | `ready_after_adr` | Authenticated owner reads and truthful provenance; no frontend or execution owner needed for basic Observe. |
| Door admission (`chio api protect`) and kernel-owned tools | `prevent` | `ready_after_adr` | Only calls authorized before dispatch at the owner's own door. |
| Hook-mode host observation | `detect_only` | `ready_after_adr` | Hook absence, timeout or crash can leave a tool running. |
| Native approval, per-task closure, kernel stop | `prevent` | `ready_after_adr` | Owner decisions before effect; S28, S4 and S8 gate each separately. |
| Protected harness launch | `prevent` | `ready_after_adr` | Each host needs its own installed I01-I08 and H01-H05/H06a/H08a. |
| Native-shell sandbox interior | `cannot_see` | `deferred` | No per-write decision or receipt inside a host's own sandbox. |
| Herdr and optional Omarchy/workbench consumers | `advisory_only` | `ready_after_adr` | Presentation and navigation; never an issuer, ledger or required service. |
| Cross-host custody transfer and live migration | `prevent` | `deferred` | Separate owner contracts; not implied by delegation or cooperation. |
| Compositor control and configuration repair | `cannot_see` | `hard_skip` | Removed from this program. |

## HOST-M1 on Omarchy

HOST-M1 (NORTH-STAR-FLOWS section 3) runs on two independently operated hosts. On Omarchy it is cut server-first (roadmap COOP-1): headless services and the door come first, desktop review moments are optional follow-ons and never gates (roadmap COOP-1). An Omarchy host can be either Org A or Org B.

**Services.** `chio trust serve --advertise-url` and, on the executing side, the governed tool behind `chio api protect` with `CHIO_TRUSTED_ISSUER_KEY` set to the local trust-control authority key. Both run as systemd units: user-session units for a personal install, or a system service under a separately enrolled unprivileged service identity for an always-on principal. Installation places inert units; activation requires the profile's enrollment. HTTPS reachability uses existing lanes; iroh is not needed.

**Custody.** Signing uses key references on #1160's `signing_custody` (F, main experimental). Desktop sessions use Secret Service through the desktop keyring; headless service principals use `systemd-creds` (`credential:` references, TPM2-sealed where the host has one). Verify both on the target host. Plaintext seed files are a labelled development profile only. A key missing from custody, a locked keyring or an unavailable credential refuses; there is no fallback to plaintext, a personal login or another principal.

**Local operator IPC.** `chio-secure-ipc` with `SO_PEERCRED` (F, main experimental), extended as described under services below.

**Cases.** HOST-M1 consumes C09, Q05, Q06, Q24, Q28 and Q29, plus Q31 for every time-bounded read, approval, challenge and service lease. Q05/Q06 attribution needs S28 and a production passkey verifier; until then approvals are labelled `SharedCredential`. The installed approval utility must bind the exact decision and approval ID (backbay-labs/chio-bridge#3); a wrapper refusal does not repair a directly callable affected binary.

### Optional review moments

A notification opens a review page, the QML bar shows identity and the count of pending reviews, and a package-owned Walker entry opens reviews. They consume the same native authority as any client and add no task editor, issuer or browser dependency.

The optional shell plugin uses ID `computer.chio.desktop`, kinds `bar-widget`, `panel` and `service`, and `keepLoaded: false`. [Upstream research](research/omarchy-upstream.md) pins release v4.0.4 at `c668141e9c42b13c80c9ca4ea108e11708c5e8a5` and observed development HEAD `0f8af9be307d5d4f12cc0f6394892cac651ed5e6`; each is a separate compatibility candidate and neither is qualified.

| Platform behavior | Required adaptation |
| --- | --- |
| `shell` and `manifest` injected after QML object creation | Start one client only after properties are ready; repeated injection is idempotent. |
| Reload destroys nonretained services, widgets and panels | Generation-bound callbacks; reload disconnects only the presentation shim and never replays commands. |
| Widgets on several monitors | One shared subscription; no per-monitor client or polling fallback. |
| Replacement bars may omit `omarchy.bar` | Show unavailable state; never traverse QML parents to bypass facades. |
| Panels receive queued navigation payloads | Navigation-only routes and opaque owner IDs; no paths, commands, tokens or approval bodies. |
| HEAD has helpers absent in v4.0.4 | Feature-probe `ShellIpc` and `Style.duration` with static fallbacks. |
| Notifications persist with click actions | Generic text, `app_name=Chio`, normal urgency, fixed opener, DND respected; a historical click refreshes owner state and cannot grant, retry or publish. |
| Third-party QML is desktop-user code | Facades and socket modes do not isolate malicious same-UID plugins. |

Use upstream `Color`, `Style`, `Border` and panel primitives, Accessible names/roles/states/actions, text plus shape for status, keyboard focus, reduced motion and IME-safe input (suspend `PanelKeyCatcher` while an editor owns input). Acceptance is rendered: keyboard, AT-SPI, large text, themes, IME, multi-monitor focus and lock privacy. QML stores visual preferences only and clears sensitive detail on lock, unknown lock and disconnect. A package-owned shim uses literal absolute argv and bounded streams through the common codec, passes no prompts or secrets through argv, environment, notification actions or journald, and never self-installs, invokes a package manager or imports secrets.

## HOST-M2 on Omarchy

HOST-M2 (NORTH-STAR-FLOWS section 4) runs one root grant across Claude Code, Codex, Pi and Hermes on one Linux host. Before the success test this is the executing organization's platform. Owners are #1160's (F): the `integrations/required-agents` container resource and four-tool gateway, the `chio process` host (needs pidfd), the Linux-only `chio-secret-broker` and the model relay.

**Order.** Pi with its restricted bubblewrap profile first; then Linux restricted launchers for Claude Code, Codex and Hermes, one host at a time, following Pi's profile in each plugin repository; then the Megastart Linux port so Herdr can coordinate on Omarchy. Each host promotes on its own installed I01-I08 and H01-H05/H06a/H08a; H06b (all four mixed) and the Herdr H07/H08b matrix gate aggregate completion only. No host substitutes for another, and the Pi bubblewrap profile is not a backend for the others. Historical Pi plugin 0.1.0/Pi 0.85.1 results qualify nothing current. Cursor and OpenClaw keep their broader doc 19 obligations.

**Cases.** HOST-M2 consumes C02-C05, C10, C11, Q03, Q07, Q08, Q11-Q13, Q15, Q19, Q22, Q23 and Q25-Q27, plus H01-H08 for each harness. Megastart's allowance moves onto kernel holds before it coordinates (NORTH-STAR-FLOWS section 4); application counters are not a ledger.

**Coordination and delegation.** Applications own planning and assignment; native owners keep work identity, resource generation, authority, capacity and original-operation recovery. Selected delegation qualifies its actual serving route, supported depth and allocation form, narrowing and ancestor revocation through C10/Q25; a one-hop aggregate profile stays one-hop. Linux UID maps and cgroups are not organizational authority or a globally atomic budget.

**Herdr consumer.** Once the Megastart Linux port lands, Herdr consumes these contracts through its own plugin binding under H07 and H08b, separately for each harness selection and with only the selected harness installed. Wrong principal or audience, stale tuple, expired or revoked authority, lost post-effect replies and reconnect preserve native disclosure boundaries, original identity and uncertainty without duplicate effects. Closing, reopening or unlinking its pane keeps mission state while the host continues; crashing or removing Herdr cannot renew grants, delete custody or resume work. Its UI is never a dependency of headless services.

**Model routes.** Every token or spend bound required by a grant, policy or profile must be enforceable on the exact route before dispatch (HOST-CONTRACT model-provider resource boundary): a hard output ceiling and, for money, a worst-case reservation. A missing bound refuses before credential release; a narrower profile is never an automatic fallback.

### Launch paths

Protected mode removes native-shell and direct execution routes, uses gateway file tools and denies bypass. Hook-only mode stays `detect_only`. The upstream launcher's auto-approved modes are not Chio protection. Do not shadow `pi`, replace `omarchy-agent`, change the default agent or edit upstream aliases and bindings. When the desktop consumer is selected, a package-owned desktop/Walker entry, **Launch default agent in protected mode**, resolves and displays the selected host, then requires its exact qualified I01-I08 tuple; unsupported selections explain why and never silently launch the auto mode. Menu customization uses explicit onboarding, one owned key and a literal opener, and preserves unrelated JSONC.

### Isolation evidence

S7 must add or qualify `AgentHostBwrap` before any consumer asserts it; `ProcessContainer` covers a qualified container backend; unknown kinds are unconfined. `chio-cage` stays a tool-server profile and does not run Node or Pi; this program neither forces Node into it nor relaxes it. Agents receive only qualified gateway and relay descriptors and their workspace closure: no operator endpoint, provider secret, authority store, SSH agent, desktop bus, compositor socket or engine socket. Measure filesystem, raw network, inherited descriptors and subprocess escape from outside the guest (Q12, Q22). The historical privileged ARM64 bubblewrap run is research evidence, not Omarchy acceptance; exact x86_64 Linux is measured first and the Omarchy tuple separately.

### Container engines

If the optional `chio-mini-swe` reference workload is selected, rootless Docker is its candidate engine. The inspected runner rejects `name=rootless`/`name=userns` and pins `/var/run/docker.sock`, so that profile needs a runner-owner change before qualification. Pinned Omarchy installs Docker with its system socket enabled but withholds docker-group membership; membership is root-equivalent, so a rootful profile is a separate documented opt-in whose daemon and runner join the containment TCB ([engine research](research/linux-platform.md#container-engine-privilege-and-compatibility)). Rootless Podman is a separate candidate qualified against the runner's actual calls, never an alias. Only the trusted host-side runner reaches the engine endpoint, bound to the measured endpoint and configuration regardless of `DOCKER_HOST`, contexts or user config. Guests receive no engine socket, API credential, connected descriptor or docker-group privilege; verify effective credentials. Lost rootless support refuses without rootful, sudo or unrestricted retry. Mini-swe absence never blocks a required harness or Herdr.

### Execution resource bounds

The runner and resource owners enforce, before admission, finite per-task and aggregate limits, each mapped to a real native mechanism with independent measurement. Missing or ineffective enforcement makes the dependent execution profile unavailable (Q19, Q22, Q27):

- **Stored bytes and output.** Writable volume/layer, temporary, cache and inode budgets, stdout/stderr ingress, buffering and retention, and engine logs, journals and spool files outside the container. Reserve measured capacity for receipts, original-operation state, stop and recovery; exhaustion refuses admission or stops work before that reserve is consumed, and evidence is never deleted to make room.
- **Storage I/O.** Read/write throughput, operation rate and outstanding-I/O bounds across buffered, direct, mmap and flush paths, layered storage and engine writes. Fixed-size rewrite/reread pressure must show real device bounds while receipt, control and stop keep progressing; unsupported paths are denied.
- **Descriptors and IPC objects.** Per-class and aggregate bounds on descriptors, pipes, sockets, eventfds, epoll instances, queues and allowed shared-memory objects, including host allocations triggered by guests, with reserved native control capacity. A per-process descriptor limit does not bound every class; unneeded classes are denied.
- **CPU, memory and PIDs.** Measured cgroup v2 delegation and effective limits on the actual cgroup; accepted flags prove nothing. Keep one cgroup writer per delegated subtree.
- **Fresh task-private state.** Each task gets fresh private writable state. Same-user and cross-user, sequential and concurrent canaries prove no source, secret, result, tool state or queued authority carries over through home, temp, cache, IPC, retained descriptors or reused runtime state. Shared caches must be declared, content-addressed, immutable and verified against the current authorized input closure; writable, secret and result caches are never reused across tasks. Unresolved cleanup fences reuse, and a new task ID or recreated directory alone does not prove freshness.

### Repository and working-tree capture

Capture is a resource-owner boundary before any model, runner or evaluator sees input (Q14, Q22). Repository-controlled configuration, attributes, hooks, filters, helpers, lazy fetching, replacement refs, alternates and external object sources cannot cause host reads, processes or network fallback. Git object parsing enforces per-object and aggregate encoded and expanded bytes, object count, graph and delta depth, CPU, memory, time and staging limits before materialization; bombs and malformed objects refuse before dispatch. Working-tree reads have their own byte, entry, depth and staging caps and refuse FIFOs, sockets, devices and unproved outside links. The capture owner must produce a coherent whole-tree generation, from an immutable atomic snapshot or a proved writer-complete fence covering every writer, or refuse; per-file hashes, stable metadata and advisory locks are insufficient. It binds the approved mount closure to descriptors and native mount identity, so pre-existing or raced bind/FUSE mounts below the root, and root, ancestor or subtree mount replacement (including between read chunks, across owner restart and with retained descriptors), refuse before outside bytes are read; path prefixes, unchanged device numbers or a one-time mount census are not proof. An oversized or interrupted capture refuses rather than being accepted as truncated input. Confinement after capture cannot substitute for any of these.

### Process custody and execution clocks

`chio-process` remains the custodian; systemd and cgroups enforce host lifetime and resources, not work identity. A dedicated fixture worker establishes child-subreaper custody before hostile descendants start and reaps within a bound; double-fork, process-group escape, full pipes, timeout and stop escalation are exercised, and absence is proved by an independent process/cgroup census (Q19). Each stop and cleanup phase has an explicit deadline; if absence or the original outcome cannot be established, the owner reports it unresolved and keeps recovery custody. Neither SIGKILL nor a clean systemd state proves a remote effect absent. Execution profiles bind local task lifetime to boot identity and a suspend-inclusive `CLOCK_BOOTTIME` deadline, retain the authority's absolute expiry as a separate bound, and fence protected continuation on resume until owner revalidation ([clock research](research/linux-platform.md#upstream-linux-conclusions)). Missing clock enforcement disables that execution profile, not basic Observe.

## HOST-M3 on Omarchy

HOST-M3 (NORTH-STAR-FLOWS section 5) needs HOST-M2 on the executing owner's platform, so before the success test the executing organization runs Omarchy or another qualified Linux host. A macOS-only party takes part as the requester. The executing Omarchy owner must:

- run as a separately enrolled organization principal with its own keys in OS custody, its own policy and stores, and the right to refuse; no party holds both co-signer keys;
- admit the foreign work at its own door, with receiver-owned admission in a serving path (COOP-3), and run it inside its own HOST-M2 tree and pool under one root grant with holds;
- resolve a lost reply by original identity with no second dispatch, and keep execution, acceptance, delivery and any settlement as separate facts;
- export the door's receipts in the evidence package so the requester verifies them offline against a pinned partner card.

Cases: C06, C07, C08, Q01, Q02, Q14 and Q28. A two-user local simulation cannot pass an organizational case. Unpaid work needs no funding rail.

## Services, custody and IPC

| Profile | Linux contract |
| --- | --- |
| User-session host | One explicitly enrolled graphical login session per UID, bound to native UID, boot and logind identity and client incarnation. Runs without a GUI but keeps lock and logout fences. |
| Service host | A separately enrolled unprivileged service principal with installation and boot identity, finite scopes and expiry, credential custody and boot/restart reconciliation. Login-independent work requires this owner's explicit grant. |
| Embedded host | An application embeds the kernel at a declared trusted boundary and qualifies each consumed port; not proof of confinement. |
| Optional presentation | Clients with their own scoped identities; closing them cannot delete custody, renew capacity or resume an original. |

**User session.** A per-user systemd manager or socket is not proof of a login session. Refuse a second concurrent session for the same UID; lingering never preserves human session authority. Lock, logout, unknown liveness and missed observations fence affected disclosures and actions; closure covers only original references bound to that session, never a user-wide or `Kernel` stop. Re-enrollment follows original-custody reconciliation.

**Service host.** Do not infer authority from root, UID equality, detached launch or linger. Qualify cold boot without login or an unlocked keyring, credential rotation and revocation, lease expiry, duplicate instances, interrupted enrollment, boot changes and decommission. Until these owner artifacts exist, login-independent operation is unavailable.

**Peer identity.** The inspected secure IPC owner authenticates one exact expected PID/UID/GID; a multi-client service needs an owner extension for enrollment, retained process-instance identity and authorization. Racy `/proc` lookups and `XDG_SESSION_ID` cannot fill that gap. Qualify inherited descriptors, PID reuse and client replacement (Q10, Q29).

**Transport pressure.** Every exposed listener bounds, before authentication and in aggregate independently of claimed identity, pending and active connections, backlog, descriptors, authentication workers, queues, cost and buffered bytes, with absolute non-renewing handshake and partial-frame deadlines. Reserve measured control headroom so established and freshly connecting legitimate clients keep useful progress under floods. After authentication, per-principal and aggregate request, cost, concurrency, subscription, response-buffer and slow-reader limits apply; event loss is explicit and dispatched outcomes stay under original custody (Q09, Q10, Q21).

**Time-bounded authority (Q31).** Each protected read, subscription, snapshot, approval or challenge credential and service lease names its owner, clock and freshness basis. Expiry followed by realtime rollback, forward jumps, suspend, restart or boot change, or a missing basis, refuses and never revives the old authority. These cases apply without execution owners.

| Linux need | Existing owner |
| --- | --- |
| Work, acceptance, resources | W1 contracts and resource owners; task and review UX stay in the client. |
| Original-operation recovery | Recovery `InspectWorkflow`, `SubmitApproval`, `ResumeWorkflow`, `CancelWorkflow`, W1 queries and S9 M20 retry classes; unknown effects never become fresh operations. |
| Events | S5 Part B for exposed subscriptions; no polling loop over `InspectWorkflow`. |
| Stop | S4 phases 1-2 for one task; S8 phase 1 for durable `Kernel` stop, with `Tenant`/`Recovery` after phases 4/5. Logout never implies a global stop, and a stop receipt never claims an admitted effect was undone. |
| Credentials and providers | Existing broker and model relay; no plaintext fallback when the store is locked or removed. |
| Shared resources and crossings | Capacity, work, resource, federation and disclosure owners with CASES evidence. |

Basic receipt and hook Observe works with W1, recovery and execution owners absent and attempts no reads or subscriptions to them. The optional `chio.operator.v1` controller stays outside the TCB, holds no signer or ledger, and is never the kernel ABI.

## Packaging and lifecycle

**Packages.** Delivery roles stay separate: native owners and the `chio` CLI; Linux adapters, units and profile configuration; harness and application adapters; and the optional Omarchy shim, opener, desktop registration and QML plugin. Native packages have no workbench, Qt, Quickshell or Hyprland dependency. The first candidate uses pacman-compatible signed archives with fixed public inputs, SBOM and build records; protected runtimes never resolve through `mise`, ambient `PATH` or a developer checkout. Final package names come from implementation.

**Units.** Role-specific units with tested hardening, bounded restart and stop, restrictive umask, core-dump suppression, fixed paths and minimal environment. User-session onboarding never enables lingering, imports the user environment or creates a root controller; service-profile boot provisioning is a separate recorded choice. An unsupported unit option must not become silent partial protection.

**Support tuple.** A support record binds one profile to: public sources and binaries; distribution, kernel, systemd, architecture and effective namespace, cgroup and LSM probes (plus Omarchy, Quickshell, Qt and Hyprland only for a selected shell); harness, plugin, runtime, backend and image identities; engine mode, socket, configuration and UID maps where used; every finite resource, I/O, descriptor, transport and capture bound with its enforcing owner; provider route and account; deployment profile, enrollment and credential context; and the Q31 and execution clock contracts. Source presence, history, manifests and signatures are separate facts from a supported tuple. Omarchy's post-update hook runs before later runtime updates and cannot certify compatibility; remeasure at startup, reconnect and admission. Changed QML invalidates only its optional consumer.

| Transition | Required behavior |
| --- | --- |
| Plugin load, unload, reload | Presentation connects or disconnects only; no task, approval or stop is synthesized. |
| Controller crash or restart | Reconnect, reload projections and unresolved originals; no new work or replay. |
| Lock or unknown lock | Conceal sensitive UI and disable new operator mutations; admitted work stays within its scope and expiry. |
| Unlock | Fresh identity, compatibility and snapshot; no expiry extension. |
| Suspend, resume, clock uncertainty | Owners revalidate authority under Q31; execution enforces the boottime deadline and absolute expiry. |
| Logout or session loss | Stop new admission; S4 and process custody close bounded local work, retaining unresolved effects, even under linger. |
| Service boot, restart, lease revocation | Verify enrollment, boot identity, credentials and custody before admission; grants are not renewed. |

**Candidates and promotion.** Publish explicitly unqualified, independently retrievable candidates before the clean-install campaign. Each profile promotes against its own installed evidence through the shared release verifier and Linux activation wiring (shared packet 2a; 2a-macos does not gate Linux). Protected hosts need no prior sealed-coding release. These documents invent no repository or package URL. Each case records its trigger, independently observed result, exact tuple, owning gate and negative controls; unknown, refused, skipped and passed stay distinct, and a required unexecuted case leaves the profile unqualified. Removing any required result from an otherwise passing manifest must make the affected activation or promotion refuse. Security updates invalidate new admission for affected tuples; a replacement needs its own signatures, provenance and qualification, and an advisory never resumes a task or broadens a grant.

**Optional plugin install.** `omarchy plugin add` takes a repository URL and `--yes` (without `--enable` it installs disabled), not a revision. Verify the signed lock and absence of an existing plugin; add with `--yes`; `git checkout --detach` the locked commit; verify HEAD, ID, every file path, mode and digest and the native pairing (a clean Git status proves none of these); run `omarchy plugin validate`; only then `omarchy plugin enable computer.chio.desktop`. Never invent `--ref`, `--revision` or archive flags. Upstream updates change the plugin independently and require verification again.

**Upgrade, rollback and channels.** Package installation and state migration are separate transactions; pacman scripts never mutate work stores, enroll credentials or resume tasks. Quiesce admission, migrate through owners, activate a coherent tuple and reconcile before new work; interruption leaves explicit unavailability, never mixed-generation execution. Across update, rollback, migration and generation revocation, established native, subscription and browser channels are closed or revalidated (both peers, current authority and accepted generation) before any further protected release or dispatch, including queued requests and buffered events; a retained old helper or cached authorization cannot bypass the fence (Q20, Q31). Omarchy root snapshots leave `/home` and `~/.config` unchanged, so an older binary refuses incompatible writes; receipt anchors, reservations and revocation never move backward.

**Backup and removal.** Use owner backup and snapshot interfaces, never copied live SQLite files. Restore stages privately and reconciles against current authority and external effects before execution. Plugin removal disconnects presentation; backend removal reports unresolved work, stops boundedly and preserves owner state, receipts, artifacts and backups. Purge is a separate destructive workflow blocked by unresolved custody. ENOSPC, inode exhaustion, EIO and read-only state refuse explicitly without deleting history.

| Linux case group | CASES rows | Plan packet |
| --- | --- | --- |
| Peer, session and service enrollment | Q10, Q29 | O1 |
| Transport pressure and Observe independence | Q09, Q10, Q16, Q21, Q23 | O1, O7 |
| Time-bounded authority | Q31 | O0, O1, O4, O7 |
| Approval and stop | Q05-Q08 | O4 |
| Required harness launch | H01-H08, Q11-Q13, Q22 | O5 |
| Execution bounds, private state, custody | Q12, Q19, Q22, Q27 | O3 |
| Capture bounds, coherence and mounts | Q14, Q22 | O3 |
| Coordination and shared resources | C02-C05, C10, C11, Q25-Q27 | O3 |
| HOST-M1 cooperation | C09, Q24, Q28 | O1 |
| Organizational cooperation (HOST-M3) | C06-C08, Q28 | O3 |
| Mutations and helper operands | Q02, Q17 | O0, O7 |
| Distribution, update, rollback, recovery | Q18, Q20, Q30 | O6, O7 |
| Optional shell and browser | Q04, Q10, Q17 | O2 |

**Diagnostics and privacy.** Component-specific diagnostics carry observation time and profile identity. Logs hold fixed codes, bounded counters and redacted identifiers; prompts, source, credentials, approval bodies, raw paths and core dumps are excluded. Local export is size-capped with an omission marker; sharing is a separate action. Never poll recovery inspection to render a spinner.

## Herdr

Herdr is a third-party terminal workspace application for coding agents
(https://herdr.dev/docs/, version 0.9.3 inspected 2026-10-08). "Herdr support"
in this program currently means Megastart's Herdr plugin (G in PROGRAM-MAP).
Megastart's native composition requires Apple Silicon macOS, so Linux Herdr
cases stay blocked until the Megastart Linux port lands (NORTH-STAR-FLOWS
section 9). Herdr never issues kernel authority.
