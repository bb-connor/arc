# 08. Linux confinement and host lifecycle

Status: Proposed.

Confidence: high in the required trust and enforcement distinctions, based on [primary-source research](research/linux-platform.md); moderate in feasibility of the complete deployment until actual x86_64 Omarchy qualification. No proposed controller, service composition, profile or acceptance case below is represented as implemented.

Scope: the first Omarchy x86_64 project-task profile, its Pi guest, fixed test recipes, protected resource adapters and Linux lifecycle. Dependencies: P0 platform/native prerequisites; shared authority, protocol, task/recovery and credential contracts; [distribution operations](12-distribution-operations.md). P2 requires the relevant runtime gates below. P3 through P6 introduce additional capabilities and require additional qualification rather than inheriting approval from P2.

## Capability and selected architecture

Chio's role is to give agent work a bounded execution environment connected to native authority and recoverable effects. The desktop controller presents and coordinates that work. Enforcement is the composition of the existing Chio authority/kernel, protected resource adapters and measured Linux boundaries.

The default threat profile trusts the desktop user, installed shell plugins, administrator, package publisher and kernel. It treats model output, agent code, repository contents, test output and resumed guest state as hostile. The QML shell plugin is arbitrary user code; a same-user socket, file modes or peer UID check cannot defend against a malicious plugin running as that user. The first release must state that boundary plainly. Stronger protection from the local desktop user would require a separate principal/VM and independently designed operator authentication.

| Role | Access permitted by the proposed profile | Access prohibited |
|---|---|---|
| QML plugin and literal-argv client shim | Versioned operator protocol and bounded redacted projections | Signing keys or direct implementation of authority, approvals or recovery |
| Thin Rust controller | Task custody, native Chio client operations, trusted service/lifecycle observations | Inventing execution receipts, relaxing native refusals or issuing replacement native operation IDs to evade uncertainty |
| Trusted launcher/model relay | Exact qualified runtime, fixed authenticated routes, specifically scoped credentials | Guest-selected destinations, arbitrary desktop commands or passthrough administrative protocol |
| Pi guest | Pinned Pi bootstrap, private task state, fixed gateway/model relay leaves | Desktop/session control, provider credentials, native authority state, host project source, arbitrary host tools |
| Test recipe | Exact immutable source generation and declared runtime, private scratch, fixed command | External network, arbitrary shell, writable host project, additional subprocesses unless separately profiled |
| Protected resource adapter | Its own authenticated manifest/topology and bounded resource authority | Assuming Pi namespace enforcement covers its separate process or accepting guest claims as evidence |

Select separate profile identities for the Pi guest, each fixed recipe and each native resource. The native strict cage source is a separate prerequisite artifact (`LINUX-NATIVE-CAGE-INSPECTION` in the research map); it uses an independently enforced Landlock/seccomp contract and does not supply namespaces/cgroups by itself. Do not claim arbitrary Node/Pi fits it. If the proposed protected coding resource cannot run under an available qualified native profile, P2 is blocked pending a compatible implementation or independently reviewed resource profile. The controller cannot remove the gate. Native approval decision remains a separate open prerequisite: until its exact authority path is available and qualified, `approval.submit` must refuse; a desktop dialog does not supply that authority.

Rejected alternatives: unrestricted Pi in a user service; exposing the compositor/session bus to the guest; adopting an executable allowlist as confinement; widening the strict cage merely to satisfy a Node import; treating a successful privileged-container probe as actual desktop qualification.

## Normative contract

Every SHALL below is a proposed requirement. Numbers are initial proposed policy defaults, not measured product limits; a release profile may choose stricter values and records them in its signed/support manifest.

| Requirement | Contract | Acceptance |
|---|---|---|
| OM-LNX-001 | Execution SHALL require a named x86_64 Omarchy support tuple and positive effective-feature probes; unsupported hosts retain read-only diagnostics and refuse mutation without a privileged or unconfined fallback. | AT-LNX-001 |
| OM-LNX-002 | Guest, recipe and native-resource enforcement SHALL have distinct manifest/profile identities and independent qualification; controller and trusted shell are outside the guest security boundary. | AT-LNX-002 |
| OM-LNX-003 | Admission SHALL bind the entire immutable runtime/mount closure and retain its identity through launch; additions, replacements, aliases, unresolved dependencies or executable mismatch refuse launch. | AT-LNX-003 |
| OM-LNX-004 | Guest admission SHALL prove unprivileged user, mount, PID, IPC, network and UTS namespaces, private process/device views, no new privileges and dropped capabilities under the actual service. | AT-LNX-004 |
| OM-LNX-005 | Each executable profile SHALL use its independently qualified architecture-specific seccomp policy and required Landlock rights; missing or partial mandatory enforcement refuses launch. | AT-LNX-005 |
| OM-LNX-006 | Guest communication SHALL be restricted to exact authenticated Chio/model routes, with operator, compositor, session, SSH, container, portal and other ambient sockets absent and unreachable. | AT-LNX-006 |
| OM-LNX-007 | Environment, argument vectors and inherited descriptors SHALL be constructed from explicit public allowlists; provider/operator credentials remain outside guest-visible files and process attributes. | AT-LNX-007 |
| OM-LNX-008 | Parent publication into or from guest-controlled storage SHALL use race-resistant retained-directory operations, exclusive temporary files and durable atomic commit, with no symlink/hardlink traversal or unverified destination replacement. | AT-LNX-008 |
| OM-LNX-009 | Every guest and recipe SHALL have effective task-scoped memory, process/thread, CPU, time, output and writable-storage bounds; admission refuses unavailable mandatory controls. | AT-LNX-009 |
| OM-LNX-010 | Stop, timeout, parent crash and service failure SHALL terminate the whole owned process tree and verify absence without relying on a signalled PID or wrapper exit alone. | AT-LNX-010 |
| OM-LNX-011 | Local lifetime accounting SHALL include suspend, bind to boot identity and preserve original cumulative reservations; restart, wall-clock rollback or checkpoint restore cannot renew authority or budget. | AT-LNX-011 |
| OM-LNX-012 | Suspend/resume SHALL stop new admission, bound local shutdown and require authority/operation reconciliation before any resumed work; uncertainty remains visible and fenced. | AT-LNX-012 |
| OM-LNX-013 | Lock, unlock, logout and shutdown SHALL follow the explicit session policy below, including missed events, lingering user managers and multiple graphical sessions. | AT-LNX-013 |
| OM-LNX-014 | Credential or route renewal SHALL occur only in the trusted native/relay path, bind the original task authority and invalidate stale transports without widening the guest profile. | AT-LNX-014 |
| OM-LNX-015 | ENOSPC, inode exhaustion, EIO, read-only filesystems, torn persistence and unexpected unmount SHALL fail closed while retaining operation identity and recovery evidence. | AT-LNX-015 |
| OM-LNX-016 | Project material and recipe effects SHALL cross through protected source-generation/test/publication adapters; a confined test success alone cannot authorize publication. | AT-LNX-016 |
| OM-LNX-017 | Health/status SHALL distinguish configured intent, observed enforcement, native evidence and qualification; host diagnostics and UI events are never substituted for execution receipts. | AT-LNX-017 |
| OM-LNX-018 | A release SHALL include independent positive and negative actual-Omarchy evidence for the complete selected tuple, including externally observed effects and lifecycle cleanup. | AT-LNX-018 |

### Platform and runtime admission

The first target is an ordinary non-root user on actual x86_64 Omarchy. A disposable x86_64 Omarchy VM is acceptable only when it boots the selected image and its actual desktop/session stack, records its virtualization boundary and runs without privileged-container exceptions. Bare-metal acceptance remains separately labelled. ARM64 and other Linux distributions are additional targets requiring separate evidence.

Measure kernel release/configuration, active Landlock ABI/handled rights, effective seccomp and `no_new_privs`, user-namespace creation, cgroup v2 controllers, pidfds, `openat2`, `close_range`, sealed memfds, `execveat`, retained-object mount identity, required parent-child ptrace semantics and descriptor limits. The inspected native candidate's source floor is Linux 6.7, Landlock ABI 4 and x86_64; that floor is neither a guarantee that a newer host works nor an independently qualified Omarchy version. Do not silently enable kernel knobs, disable an LSM, grant extra capabilities or switch to setuid bubblewrap. The proposed first bubblewrap package is non-setuid. [Kernel Landlock API](https://docs.kernel.org/userspace-api/landlock.html), [bubblewrap policy documentation](https://github.com/containers/bubblewrap/blob/v0.11.0/README.md)

The runtime manifest binds executable and bootstrap hashes, architecture, resolved ELF interpreter and every required shared object, Pi/bridge dependency inventory, seccomp bytes, namespace/mount plan, accepted environment, descriptor plan and permitted relay endpoints. Package files are root-owned immutable generations. The operator cannot select a home directory as a runtime tree. A directory-wide read-only `/usr`, `/home`, installation parent or runtime parent bind is not an acceptable substitute for an exact closure. A signed inventory is checked against actual files at launch; package metadata alone is insufficient. Retain safe object identities across verification and execution, or use a qualified immutable-generation mechanism that excludes replacement races. Reject device files, FIFOs, sockets, escaping symlinks, aliased mutable hardlinks and unexpected mounts in all admitted trees.

The guest gets a private `/proc` for its PID namespace, a minimal device set and bounded writable scratch. It does not get host `/proc`, `/sys`, cgroup migration files, full `/run/user/<uid>`, host `/tmp`, display devices or host home. Block nested namespace creation after setup. The launcher itself may require namespace syscalls; guest restrictions apply before guest-controlled code starts and are separately verified for the launcher's init/reaper. No syscall filter is inferred merely from a matching `Seccomp` field.

Use the Pi guest's measured thread-compatible filter only for the pinned Pi runtime. It must deny process creation, later namespace changes, cross-process memory/descriptor access and unreviewed asynchronous syscall bypasses; qualify x32 handling on x86_64. Recipe filters are separate and deny socket creation. Native strict-cage requirements remain strict. An observed Node import failure is a compatibility failure, not permission to broaden any filter. [Seccomp API](https://docs.kernel.org/userspace-api/seccomp_filter.html)

### Communication, credentials and environment

A Pi guest may see only the two named relay leaves for its task, mounted individually or passed as specifically authenticated connected descriptors according to its profile. No parent directory is mounted to expose sibling sockets. Pathname and abstract Unix sockets, inherited FDs, loopback, IPv4/IPv6, DNS, alternate HTTP Host/method/path, redirects, CONNECT and descriptor-passing paths are tested. The relay accepts only fixed provider/model and native tool routes and enforces the existing task-bound capability. The operator AF_UNIX NDJSON socket never enters the guest. A read-only bind is not a socket access-control mechanism. [systemd execution caveats](https://github.com/systemd/systemd/blob/v258/man/systemd.exec.xml)

Start with an empty environment. Proposed public values include a fixed locale, task-only `HOME`/`TMPDIR`, literal package executable directories and explicit bootstrap routing identifiers. Remove loader/preload variables, `NODE_OPTIONS`, language module search paths, shell startup variables, Git configuration/credential helpers, proxy variables, `DISPLAY`, `WAYLAND_DISPLAY`, compositor signatures, `DBUS_SESSION_BUS_ADDRESS`, `SSH_AUTH_SOCK`, container endpoints and all inherited Chio/provider tokens. Trusted components also use controlled environments; they do not source the user's shell or `mise` initialization.

Provider credentials and authority signing material stay in trusted custody. A short-lived scoped relay bearer may be delivered through a dedicated inherited FD that is bounded, consumed and closed before Pi runs; it is not a provider credential and cannot authorize administrative calls. No secrets in argv, bubblewrap `--setenv`, unit environment, diagnostics or journal messages. Close every unnamed FD before exec; test with planted secret files and connected sockets. Peer credentials/type/ownership checks and an unguessable task token supplement the guest namespace. They do not create security against hostile same-user desktop code.

Credential expiry stops new admissions. Rotation does not change native operation identity or replay an outstanding request. Close stale relay connections, bound in-flight requests by their original deadline and reconcile uncertain native effects. A task cannot choose an alternate provider after recovery to escape its original authority/budget.

### Publication, storage and lifecycle

All guest-produced paths are hostile, including a profile retained from an earlier run. Validate them before the first parent mutation. Keep transport configuration in parent-controlled storage where possible; any required in-profile publication uses a retained safe parent dirfd, constrained relative names, non-following exclusive file creation, descriptor identity checks, fsync, atomic rename and parent-directory fsync. Reject existing multiply linked or unexpected special destinations. Perform extraction, cleanup and export using the same confinement discipline. Scanning a tree followed by `writeFile(path)` is insufficient when a live worker can swap an ancestor. Quiesce and prove absence before handling mutable profile state, or use a descriptor-safe algorithm explicitly qualified against a concurrently hostile worker. [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html), [rename](https://man7.org/linux/man-pages/man2/renameat2.2.html), [fsync](https://man7.org/linux/man-pages/man2/fsync.2.html)

Initial proposed per-task defaults: one Pi worker, 2 GiB `MemoryMax`, 256 tasks including threads, 200% CPU quota, 15-minute total lifetime, 512 MiB scratch and 64 MiB persisted guest-profile export. The initial P2 fixed Node recipe defaults to 2 seconds plus 100 ms termination grace and 16 KiB combined captured output, matching the project-resource profile; total dispatch overhead still fits below the candidate 30-second native execution deadline. The 15-minute task lifetime deliberately lowers the candidate host's 30-minute model wall limit. These distinct task/recipe/native deadlines are never interchangeable. These are admission policy values pending measurement; the tuple records exact accepted values. The machine must have sufficient capacity or refuse the task. Do not silently shrink bounds mid-run or claim a disk limit that only stops reading stdout.

Use per-task systemd-managed cgroups with CPU/memory/pids controllers and a bounded filesystem or tmpfs for every guest-writable mount. Guest state copied out for resume passes a bounded parent-controlled export. If persistent guest storage is directly mounted, a qualified byte/inode quota is mandatory. Reserve at least 32 MiB in trusted state storage as an initial proposed emergency journal margin; inability to reserve or persist prevents new effects. Resource counters bound local execution, not provider billing. Provider costs remain separately measurable/enforceable according to their qualified adapter. [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

Supervision records task ID, boot ID, task cgroup identity, process start identity and retained pidfds where available. Isolated process groups support graceful termination but are not the complete lifetime boundary: a session-changing descendant can evade a process-group-only design. TERM begins bounded stop, then KILL covers the entire task cgroup. Require actual reaping, no live descendants and `cgroup.events` unpopulated before releasing ownership; reconcile namespace reapers as well. A stuck uninterruptible task remains fenced and visible rather than falsely cancelled. Kill the task subtree without killing the controller's unrelated tasks. [systemd kill semantics](https://github.com/systemd/systemd/blob/v258/man/systemd.kill.xml)

| Event | Proposed default behavior |
|---|---|
| User cancellation | Stop admission immediately; request native cancellation for the original operation; terminate local workers within 5 seconds graceful plus 5 seconds forced-observation budget. Report `cancelled` only when native/task semantics permit it. An unresolved operation remains `blocked_unknown`. |
| Controller/launcher crash | Service manager and parent-death mechanisms stop owned workers. Restart restores custody and queries original native operations before allowing resumed execution. Never infer effect absence from worker death. |
| Suspend/hibernate preparation | Enter recovery handling, stop new calls, flush original identity/reservations and stop local workers. A best-effort delay inhibitor is bounded to 5 seconds and never prevents sleep indefinitely. Abrupt suspend takes the same recovery path after wake. |
| Resume | Reprobe changed host/boot/session, query original operations and current authority/expiry, restore cumulative counters. Require explicit `task.resume` for further execution; never replay automatically because the screen woke. |
| Lock | Redact sensitive projections, disable approval submission/new admission and begin bounded stop of foreground task workers. Reconcile in-flight calls. Logind/compositor observations are usability/lifecycle signals under the trusted-shell profile, not cryptographic proof of human presence. |
| Unlock | Refresh session/authority/status. Do not restore an old approval decision or auto-resume a task. |
| Logout/session loss | Stop the bound session's tasks and controller access. User-manager lingering or a second login cannot keep those tasks authorized. Recovery state remains on disk. |
| Shutdown/reboot/power loss | Perform bounded stop if notified; otherwise recover from durable originals at next start. A shutdown deadline is not a terminal execution receipt. |

Use `CLOCK_BOOTTIME` for local deadlines on the same boot and retain boot ID plus the authority's absolute expiry. Wall-clock rollback cannot extend a task. Proposed clock-discontinuity threshold is a 5-second difference between realtime and boottime deltas; crossing it blocks new calls pending native time/authority reconciliation. Across reboot, treat local boottime values as incomparable and use authoritative expiry plus retained cumulative usage. Clock precision does not create an independent authority. [Linux clock semantics](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)

Session attachment is explicit: one qualified graphical session is selected, recorded and verified through trusted lifecycle adapters. Multiple simultaneous sessions are refused for mutations in the first profile until deterministic ownership is qualified. Missed logind/desktop notifications trigger a snapshot refresh before further execution. A transient UI disconnect is presentation `offline`/`stale`, not task success or cancellation. The task vocabulary remains `preparing`, `ready`, `running`, `waiting_approval`, `recovering`, `blocked_unknown`, `cancelling`, `cancelled`, `succeeded`, `failed`.

Persistence errors before a durable intent imply no dispatch. Errors after possible dispatch retain that original as unknown until native reconciliation. An independently observed successful resource effect does not allow the controller to fabricate a receipt after disk failure. Preserve quarantined state, reservations and receipt anchors; do not rotate logs, clean profiles or reclaim locks to erase uncertainty.

## Proposed acceptance

Each case records exact source/package/runtime/policy hashes and host tuple. An independent oracle runs outside the guest and does not accept guest output, controller status or exit code alone as proof.

### AT-LNX-001: Effective host eligibility

Trigger: start on the selected non-root x86_64 Omarchy image, then separately disable user namespaces, remove Landlock support, repeat on an ARM64 host and remove a required syscall/controller. Observable outcome: the positive control launches; every deficient case refuses before any tool/model effect and gives a specific diagnostic. Independent oracle: host-side feature probes plus protected-resource/model request counters. Evidence artifact: `lnx-001-platform.json` with probe results and zero-effect negatives.

### AT-LNX-002: Separate enforcement claims

Trigger: run a qualified Pi positive control and separately request an unqualified Node executable under the strict native cage; forge a guest status field claiming full enforcement. Observable outcome: only the qualified composition starts; the other cases cannot promote resource/cage status. Independent oracle: trusted manifest/profile verification and executable/process inspection. Evidence artifact: `lnx-002-profile-boundaries.json`.

### AT-LNX-003: Runtime and mount identity

Trigger: run the exact runtime; then replace a loader/library/bootstrap between preflight and exec, add a socket to the closure, add an escaping symlink/hardlink and change a mount destination. Observable outcome: exact positive works, each mutation refuses or safely retains the originally admitted immutable object. Independent oracle: retained descriptor identities, `/proc/<pid>/exe`/maps and outside sentinels. Evidence artifact: `lnx-003-runtime-races.json` and hashed inventory.

### AT-LNX-004: Namespace observations

Trigger: launch from the real user service and request host process enumeration, host device access, host `/tmp` access and nested namespace creation. Observable outcome: qualified bootstrap runs, host views are absent, every forbidden probe fails. Independent oracle: parent-observed namespace inode comparison, capabilities, process tree and sentinel reads. Evidence artifact: `lnx-004-namespaces.json`; container-based evidence records outer privileges separately.

### AT-LNX-005: Real syscall enforcement

Trigger: execute independent native probe binaries inside each actual profile, including valid thread/runtime controls, forbidden fork/clone variants, x32, namespace changes, cross-process memory/FD access, io_uring bypasses and socket creation where denied; force partial Landlock. Observable outcome: required positives pass, forbidden probes fail and partial enforcement prevents launch. Independent oracle: native syscall return/signal records plus host listeners/sentinels, not a mocked filter evaluator. Evidence artifact: `lnx-005-enforcement.json` and probe binary/source hashes.

### AT-LNX-006: Communication closure

Trigger: send exact allowed requests, then probe operator, Wayland, session/system bus, SSH agent, Docker/Podman, portal, abstract sockets, alternate IPs, DNS, CONNECT, wrong Host/path and descriptor passing. Observable outcome: only fixed routes reach their intended receivers. Independent oracle: independently instrumented listeners and packet/socket observations, including a canary operator method counter. Evidence artifact: `lnx-006-route-matrix.json` with all forbidden effect counts zero.

### AT-LNX-007: Secret and ambient state closure

Trigger: seed unique credential canaries in parent environment, argv templates, shell/mise configuration and inherited descriptors; run actual Pi model/tool positives. Observable outcome: allowed scoped relay traffic works without exposing provider/operator canaries. Independent oracle: external `/proc` argv/environment sampling, guest-readable inventory and diagnostic/export scan. Evidence artifact: `lnx-007-secret-canaries.json`; canary bytes are hashed/redacted in retained evidence.

### AT-LNX-008: Hostile resume and publication races

Trigger: resume a profile containing symlinked transport/marker files, multiply linked files, renamed parents and a concurrently swapping directory; interrupt before/after file sync and rename. Observable outcome: no outside file changes, no partially committed config is admitted, and uncertain publication is quarantined. Independent oracle: outside sentinel content/inode/link counts and restart readback through independent safe descriptors. Evidence artifact: `lnx-008-publication-races.json`, including 1,000 repeated swaps and each deterministic fault window.

### AT-LNX-009: Enforced resource exhaustion

Trigger: run a normal task, memory allocator, thread/process pressure, CPU loop, stdout flood, scratch byte flood and inode flood at the proposed limits. Observable outcome: normal control fits; each stressor is bounded/stopped, trusted recovery remains responsive, and unavailable controls refuse admission. Independent oracle: cgroup controller files/counters, filesystem usage/quota counters and outside observer timing. Evidence artifact: `lnx-009-resource-bounds.json` with actual maxima and chosen limits.

### AT-LNX-010: Complete descendant shutdown

Trigger: cancel, time out, kill the launcher/controller, crash the user service and exercise an independently permitted fixture descendant that changes process group/session. Observable outcome: all stoppable descendants disappear within the proposed 10-second stop budget; injected uninterruptible/unverifiable survival remains fenced, never `cancelled`. Independent oracle: pidfds, cgroup population and host `/proc` start identities. Evidence artifact: `lnx-010-lifecycle.json` with native effect reconciliation separately recorded.

### AT-LNX-011: No time or budget renewal

Trigger: start a short-lived task, suspend past expiry, roll realtime backward/forward, restart, reboot and restore an older guest checkpoint. Observable outcome: expiry/reservations never increase, original operation IDs persist and ambiguous clocks block new effects. Independent oracle: boottime/realtime/boot-ID capture and native reservation/expiry ledger. Evidence artifact: `lnx-011-time-recovery.json`.

### AT-LNX-012: Suspend and missed notification

Trigger: suspend during preparation, idle execution, active native dispatch and pending approval; repeat with the sleep signal disconnected. Observable outcome: no automatic replay on wake, workers stop/reconcile, explicit resume remains subject to original authority and unknown effects stay fenced. Independent oracle: external native/model call counter, durable-original log and post-wake process census. Evidence artifact: `lnx-012-suspend.json` including abrupt suspend.

### AT-LNX-013: Desktop session lifecycle

Trigger: lock/unlock, logout with user lingering on, close/restart the compositor, switch users, attach a second graphical session and request shutdown during an effect. Observable outcome: sensitive UI redacts, approvals/new admissions are refused while locked/unowned, workers stop and originals survive. Independent oracle: logind/session observations, compositor test harness, effect counter and cgroup census. Evidence artifact: `lnx-013-session-policy.json` plus screenshot evidence with synthetic data only.

### AT-LNX-014: Credential rotation under load

Trigger: expire/revoke the task relay credential during an active model request, then rotate through trusted custody and attempt the old bearer, changed provider and administrative method. Observable outcome: no widened access or repeated unknown effect, old transport fails, new work requires original task/authority reconciliation. Independent oracle: relay/native request audit with token hashes and destination counters. Evidence artifact: `lnx-014-credential-lifecycle.json`.

### AT-LNX-015: Disk and persistence failure

Trigger: inject ENOSPC, inode exhaustion, EIO, read-only remount and power-loss windows before intent, after dispatch, during receipt persistence and during profile export. Observable outcome: no pre-intent effect; possible post-dispatch effects become recoverable uncertainty; original IDs/anchors/reservations are retained or refusal states the precise missing evidence. Independent oracle: resource-side mutation counter and separate fsync/fault harness. Evidence artifact: `lnx-015-storage-faults.json` with recovery readback.

### AT-LNX-016: Protected project workflow

Trigger: complete the fixed edit/test/review-artifact workflow, then try direct host source writes, a changed generation, arbitrary recipe argv, failed-test lineage and unapproved publication. Observable outcome: positive artifact binds exact successful generation/test lineage; negatives cannot modify the host project or publish. Independent oracle: independent host tree hashes, resource journal and native receipt verification. Evidence artifact: `lnx-016-project-boundary.json`.

### AT-LNX-017: Honest health and evidence

Trigger: provide a configured profile with failed effective enforcement, forged guest success text, stale controller cache and malformed/unsigned receipts. Observable outcome: health names the actual blocked layer, status stays a projection and no forged receipt is accepted. Independent oracle: raw kernel observations and native verifier using pinned trust material. Evidence artifact: `lnx-017-evidence-separation.json`.

### AT-LNX-018: Independent target qualification

Trigger: a tester other than the implementer installs the final signed tuple on a clean x86_64 Omarchy host and executes all cases above, including a real native protected resource and selected provider. Observable outcome: only the exact passing profile is marked qualified; synthetic or ARM64 rows remain explicitly scoped. Independent oracle: independent effect observer, artifact signatures/inventory and reviewer replay of negative cases. Evidence artifact: `omarchy-x86_64-enforcement-qualification` containing raw results, environment manifest, test hashes and reviewer sign-off. This proposed case is currently unexecuted.

## Risks and open prerequisites

Linux security owns actual x86_64 namespace/filter/cgroup qualification, including the bubblewrap reaper discrepancy. Native Chio owns compatible resource execution and complete authority/recovery evidence. Pi owns the exact runtime closure and provider budget/transport profile. Desktop lifecycle owns actual Omarchy lock/target/logind behavior. Packaging owns quota availability, immutable installation identity and failure-safe updates. All are open before the corresponding implementation phase can claim runtime acceptance.
