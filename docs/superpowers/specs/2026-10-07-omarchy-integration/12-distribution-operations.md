# 12. Distribution and operations

Status: Proposed.

Confidence: high in Omarchy's plugin/update/snapshot constraints and the need for a separate backend package; moderate in the proposed package/unit/migration design until clean x86_64 Omarchy installation and lifecycle tests pass. Package names, new executables, units and operational artifacts below are proposed interfaces, not available release claims or commands to run today.

Scope: packaging, activation, updates, rollback, service policy, diagnosis, privacy, backup, recovery and removal for named Omarchy profiles. Dependencies: P0 source/native qualification, shared protocol/state/authority contracts, [Linux confinement](08-linux-confinement.md) and phase-specific acceptance. P7 qualifies only the explicitly named profiles whose prerequisites are complete.

## Selected distribution model

Chio is a modern Rust kernel for agentic operating systems. On Omarchy, the public desktop plugin supplies native presentation while separately installed Chio components provide authority and bounded execution. A QML plugin repository is not a backend installer.

Omarchy's Git plugin installation clones files, validates a manifest and changes enabled state; it does not execute an installation hook or ask for sudo. Plugins still run arbitrary user code once loaded. The proposed QML plugin therefore reports a missing backend and provides exact package/version requirements and operator instructions. It must not download binaries, invoke pacman, use polkit to self-install, write units, run a shell installer or obtain credentials. [Pinned plugin contract](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/manual/32-shell-plugins.md)

Proposed package split:

| Deliverable | Contents and ownership | Qualification boundary |
|---|---|---|
| QML Git plugin, proposed ID `computer.chio.desktop` | Manifest, QML, icons, presentation defaults and protocol version declaration under the user's Omarchy plugin directory | Exact plugin commit, Omarchy/Quickshell compatibility; no backend installation or authority |
| Proposed `chio-omarchy` Arch package | Thin Rust desktop controller, literal-argv protocol client shim, fixed-view opener, user units, schemas, diagnostic formatter and public docs | Signed x86_64 package, controller/shim ABI and state compatibility |
| Proposed `chio-omarchy-runtime` Arch package or explicitly versioned dependency set | Qualified Pi/Node/bridge runtime closure, fixed recipe assets, approved native helper/resource dependencies and enforcement manifests | Exact architecture/runtime hashes, source provenance and named profile acceptance |
| Existing Chio authority/kernel dependency | Versioned public artifacts providing actual task authority, signed effects/receipts and recovery | Native prerequisites must be qualified and publicly distributable; package presence alone is insufficient |
| Operator-owned state and configuration | Task journals, native original mappings, anchors, reservations, profile metadata, policy configuration and redacted diagnostics | Kept separate from code and governed by state ABI, backup and recovery contracts |

Final package naming and dependency decomposition are packaging prerequisites. Every required executable must come from a reviewed signed package or a manifest-pinned existing installation explicitly covered by the support tuple. No floating developer checkout is supported by the release profile. AUR build recipes, if later provided, remain a distinct operator-built channel with its own provenance; there is no claim of official Arch repository inclusion.

Rejected alternatives: a plugin self-updater downloading executables; relying on whichever `node` or `chio` appears in the interactive user's PATH; freezing arbitrary system packages while Arch continues to move; treating an Omarchy snapshot as a backup of Chio state; using a root system daemon to avoid designing a correct user-session policy.

## Normative contract

All requirements describe proposed behavior. Defaults below are initial proposed policy, not measured performance or current release guarantees.

| Requirement | Contract | Acceptance |
|---|---|---|
| OM-OPS-001 | QML distribution SHALL remain separate from backend/runtime package installation, with explicit missing-dependency UX and no privileged or remote-code installation side effect. | AT-OPS-001 |
| OM-OPS-002 | Every supported release SHALL publish an exact support tuple and named qualified profiles, separating source support, installation, Linux enforcement, native recovery, provider and desktop acceptance. | AT-OPS-002 |
| OM-OPS-003 | Backend/runtime artifacts SHALL be reproducibly built from public immutable inputs in recorded clean build environments, with dependency inventories, licenses and machine-readable SBOM/provenance. | AT-OPS-003 |
| OM-OPS-004 | Installation and activation SHALL require authenticated package/artifact integrity and declared publisher trust, rejecting invalid, untrusted, revoked or manifest-mismatched inputs. | AT-OPS-004 |
| OM-OPS-005 | Runtime selection SHALL use package-owned absolute paths and exact manifests; host, mise or dependency drift invalidates affected execution qualification without silently changing runtime or weakening controls. | AT-OPS-005 |
| OM-OPS-006 | Services SHALL run as the desktop user with explicit opt-in activation, bounded restart/stop policy, session ownership and no automatic lingering or global system mutation. | AT-OPS-006 |
| OM-OPS-007 | Each controller/launcher/relay/guest unit SHALL have a tested role-specific hardening matrix, effective-limit observations and explicit refusal for unavailable required protections. | AT-OPS-007 |
| OM-OPS-008 | Updates SHALL use a durable staged activation transaction that quiesces effects, validates exact runtime/state compatibility and atomically commits one generation without concurrent mixed-generation task execution. | AT-OPS-008 |
| OM-OPS-009 | Rollback SHALL preserve monotonic authority/effect custody and enforce read/write state ABI compatibility; incompatible rollback is diagnostic-only and cannot restore an old state snapshot over uncertain effects. | AT-OPS-009 |
| OM-OPS-010 | Plugin/controller protocol mismatch SHALL produce a bounded compatibility result; independent plugin reload/update never launches a second controller, repeats a mutation or claims task completion. | AT-OPS-010 |
| OM-OPS-011 | Local health and monitoring SHALL expose actionable bounded diagnostics with separate connectivity, compatibility, enforcement, storage and native-authority dimensions. | AT-OPS-011 |
| OM-OPS-012 | Logs, telemetry and diagnostic exports SHALL follow explicit data minimization, size/rate/retention bounds and local review; none is authoritative execution evidence. | AT-OPS-012 |
| OM-OPS-013 | Backups SHALL capture a consistent declared state set with manifests, required trust material and recovery dependencies, while excluding transient sockets and unnecessary credentials. | AT-OPS-013 |
| OM-OPS-014 | Restore SHALL quarantine incompatible/corrupt state and reconcile original native operations and rollback anchors before effects, without creating replacement task/operation identities to bypass uncertainty. | AT-OPS-014 |
| OM-OPS-015 | Disable/uninstall SHALL stop admission and owned processes, preserve unresolved operations and user data by default, and require a separate explicit destructive purge action. | AT-OPS-015 |
| OM-OPS-016 | Package, activation and runtime storage failures SHALL leave an independently diagnosable fail-closed state with retained previous-generation and recovery metadata. | AT-OPS-016 |
| OM-OPS-017 | Security and compatibility updates SHALL have a documented signed channel, bounded qualification ownership and revocation response without unattended authority expansion or implicit task replay. | AT-OPS-017 |
| OM-OPS-018 | Release approval SHALL require an independent clean consumer install/upgrade/rollback/backup/restore/uninstall run on the exact x86_64 Omarchy tuple, including negative cases and named scope. | AT-OPS-018 |

### Support tuple and source/build integrity

The proposed `support-manifest.json` binds:

- Public source revisions and artifact digests for plugin, controller, shim, native Chio, helpers, Pi, bridge, recipe assets, policy and schemas.
- Omarchy revision/release, Quickshell/Qt/Hyprland/session versions, Arch package versions and `.BUILDINFO` identity; `uname` architecture/kernel plus effective features measured by the Linux specification.
- Node/ELF interpreter/shared-library/runtime hashes, bubblewrap package/build/setuid status, seccomp/Landlock profile and native manifest registry identity.
- Protocol minimum/maximum version, controller state read/write ABI ranges, native recovery/store/receipt schema requirements, migration sequence, approval/delegation support and disabled capabilities.
- Named acceptance profiles, individual evidence artifacts and remaining exclusions. P1 read-only does not imply P2 execution; P2 does not imply P3 approvals/publication or P6 delegation.

Arch package version dependencies are necessary but do not replace file digests. The `PKGBUILD` uses immutable source archives/commits, verified source hashes/signatures, explicit architecture, locked dependency graphs and a recorded compiler/toolchain. Review packaging scripts as executable supply-chain inputs. Avoid install-time downloads, automatic credential setup, networked post-install code generation and build scripts that fetch unpinned dependencies. Builds occur in clean chroots with controlled network access and deterministic timestamps/paths; compare two independent rebuilds before claiming bit-for-bit reproducibility. Retain the unsigned package-content digest as well as signed distribution bytes so signature metadata does not obscure the comparison. [Arch PKGBUILD](https://man.archlinux.org/man/PKGBUILD.5.en), [makechrootpkg](https://man.archlinux.org/man/makechrootpkg.1.en), [BUILDINFO](https://man.archlinux.org/man/BUILDINFO.5.en)

Publish an SPDX or CycloneDX SBOM for Rust, JavaScript, bundled native libraries and enforcement dependencies, including licenses, source digests and vendored patches. A declared dependency version is not adequate provenance for locally modified code. The source/binary/manifest/evidence correspondence must be independently verifiable. Unpublished required source or unverifiable public revisions block public release. No private-only checkout revision appears in install instructions.

Use pacman package verification plus signed release/support-manifest verification rooted in explicit Chio publisher key identity. Retain signature verification instead of recommending `SigLevel=Never` or arbitrary key import as a workaround. Key rotation and revocation publish old/new identity bindings and the minimum accepted manifest generation. A valid signature establishes publisher/integrity, not runtime qualification. Controlled rollback may accept an older non-revoked package only when explicitly supported by the state/authority rules below. [pacman signature configuration](https://man.archlinux.org/man/pacman.conf.5.en)

No current shipping tuple is selected by this specification. In particular, source-tested Node/ARM64 versions and systemd v258 documentation references are research inputs, not the proposed x86_64 package version selection.

### Dependency drift and service policy

Backend/runtime paths are absolute package-owned paths; no shell login files, `mise` shims or ambient npm resolution participate in protected execution. User-selected model/project configuration is data. If it requires an unsupported executable or dependency, admission explains the failed pin. The package may bundle a redistributable runtime closure or depend on exact tested system SONAMEs and refuse when changed. It must not keep obsolete global libraries installed by blocking necessary Arch upgrades; the operator can update the host and leave Chio mutation disabled pending a compatible package.

Omarchy's `post-update` hook runs before its mise update, so it may signal that revalidation is needed but cannot mark the final tuple healthy. Always remeasure at service startup and before task admission; watch package/configuration changes only as a prompt to invalidate cached observations. New system libraries, a rebooted kernel, user unit overrides and modified QML each invalidate their affected qualification dimensions. Existing task identity and recovery remain accessible through compatible diagnostic paths. [Omarchy update order](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-update)

Proposed units: `chio-desktop.service` for controller custody/status and task-scoped units under `chio-tasks.slice`; separate named launcher/relay units if their permissions differ. These names require implementation and qualification. Installation places unit files without enabling them. Explicit onboarding activates the chosen user service and binds one graphical session. No `loginctl enable-linger`, root service, automatic firewall change or global environment import. Session end stops new effects even if the user manager remains alive. Do not assume `graphical-session.target` is started correctly on Omarchy; P0 must verify it and provide an explicit session adapter if necessary. [systemd special targets](https://github.com/systemd/systemd/blob/v258/man/systemd.special.xml)

Initial proposed controller policy: `UMask=0077`, closed capabilities, `NoNewPrivileges=yes`, disabled core dumps, bounded file descriptors, private runtime directory, `KillMode=control-group`, 10-second `TimeoutStopSec`, `Restart=on-failure` with 5-second backoff and maximum 3 starts per 60 seconds. Restart only restores custody/diagnostics; it never automatically resumes agent work. Bind execution units to controller/session lifetime with tested manager relationships and separate cgroups. A retained unresolved task is not a service-start failure to loop over.

| Component | Proposed hardening intent | Compatibility/qualification obligation |
|---|---|---|
| Controller | Minimal read/write state directories; Unix-domain operator IPC and the exact qualified native endpoint; no guest material execution; explicit trusted lifecycle bus access | Verify user-unit namespace protections actually apply. If controller needs process launch mediation, isolate that permission in a tested launcher role. |
| Trusted launcher | Exact executable/mount closure; only required namespace, procfs identity and native parent-child ptrace operations; no arbitrary command/argv selection | Do not blanket-deny namespace creation or ptrace needed by the approved bootstrap. Prove transition into final guest policy before untrusted code. |
| Trusted model relay | Exact provider route and credentials, bounded network operations and FD/queue counts | Host networking is confined to this role; no guest destination selector or operator socket access. |
| Pi guest | Required namespaces, no new privileges, dropped capabilities, exact seccomp, bounded writable mounts and cgroup controls | Do not apply a generic JIT-breaking rule and then disable all hardening when Node fails. Qualify the exact runtime/profile. |
| Native resource and test recipe | Own signed topology and exact profile, retained descriptors and bounded effects | Native cage receipt and actual full enforcement are separate from service-manager hardening status. |

Systemd's user-manager limitations mean that namespacing directives may need `PrivateUsers` or may not apply; some protections degrade when the host lacks support. Test effective process properties and negative probes. Read-only filesystem policy does not block Unix socket connectivity. A high `systemd-analyze security` score is supporting diagnostic output, never the release oracle. The controller itself remains trusted same-user code. [systemd execution manual](https://github.com/systemd/systemd/blob/v258/man/systemd.exec.xml)

### Credential custody and import/export

Provider credentials, native session authentication and signing/authority custody remain distinct. The existing native authority owns signing material and approval/recovery credentials; the controller must not copy these into its task database. The trusted model relay receives only its specifically needed provider credential through a qualified keyring/credential-file/descriptor mechanism. Exact storage choice is a P0 prerequisite, with owner-only parent directories, no-follow descriptor reads, explicit owner/type/link checks and encrypted storage where persistent secrets are retained. Same-user file permissions limit accidental exposure and other users; they do not protect against a malicious trusted desktop plugin.

Credential import is an explicit operator action into trusted custody, with format/size bounds and no arbitrary command execution. Do not copy arbitrary environment variables or browser/session keyrings. Values never traverse QML status, operator command argv, service `Environment=` fields, journald or diagnostic exports. If an unlock prompt is required, use the trusted custody mechanism directly; the plugin only reports availability. A locked or unavailable store blocks dependent calls without falling back to plaintext cache.

Default export contains credential identifiers and required recovery steps, never values. Any explicit secret backup uses a dedicated encrypted custody export with separately managed recovery keys. Credential removal invalidates affected transports and blocks new calls, while original in-flight operations/reservations remain subject to native reconciliation. Removing a provider key does not delete receipts or make an uncertain effect safe to retry. Package uninstall preserves encrypted custody unless the operator separately selects its removal; removing signing material requires the native decommission/recovery procedure, not recursive state-directory deletion. The privacy and restore acceptance cases include these flows.

### Staged update and atomic activation

A pacman transaction is not a transaction over user journals, plugin Git checkout, native authority and the controller's activation pointer. The proposed update coordinator is packaging/operator tooling, not the QML plugin and not a new authority engine. Package scripts may stage package-owned files and indicate required restart; they must not modify user journals or resume tasks.

The activation journal records old/new artifact digest, package identities, protocol/state ABIs, task/native original inventory, stage, diagnostic evidence and transaction ID. Its stages are `downloaded`, `verified`, `quiescing`, `staged`, `validated`, `activated`, `recovering`, then `complete` or `failed`. These are update-transaction stages, not new task outcomes.

1. Acquire exclusive activation custody; verify signatures/inventories and ensure a trusted known-good package plus recovery tools remain available. Check disk/inode reserve and compatibility before stopping productive work.
2. Stop admission, enumerate original operations, request bounded local stop and persist recovery fences. Await proved worker absence. If an effect remains unknown, an update may proceed only when the candidate has proven compatible native reconciliation semantics; otherwise preserve the old runtime and block activation. Never cancel by deleting journals.
3. Install/stage the new immutable code generation through the package manager. Keep staging separate from the active generation and reject guest/user-writable ancestors. No code is loaded from a partially extracted tree. Packaging must explicitly support overlap or preserve an authenticated package cache for reinstallation; do not assume pacman retains removed old paths.
4. Run read-only migration preflight, ABI checks, local no-effect probes and signed inventory validation. Any migration occurs with effects quiesced and a durable manifest, using the native store's migration/transaction facilities. It cannot rewrite receipt history, release reservations or change original IDs. Backups protect recovery, not permission to replay old state.
5. Fsync staged files/metadata and activation journal, then atomically replace the small generation/state binding record on the same filesystem and sync its parent. State is associated with a generation by immutable digest, never an unvalidated symlink selected by the guest. Load one generation per controller process; reconnect clients after restart.
6. Start in recovery-only mode, verify all affected host/runtime pins and reconcile originals. Expose mutation only after health and the selected profile gates pass. Mark the activation complete. Task execution still requires explicit eligible resume/new-task requests.

Atomicity means observers see a valid old or new activation record, never mixed fields. It does not promise that a power loss during pacman installation preserves executable availability. If code files are incomplete, remain stopped and use the verified recovery package; a diagnostic-only helper must not execute a partially installed controller. Updating one client while an old worker is active cannot produce a mixed-generation task: drain/recover first, or explicitly refuse activation.

### Rollback, backups and native uncertainty

Each state format declares readable versions, writable versions and migration direction. A supported application rollback changes code while retaining the latest compatible durable state and native originals. Receipt anchors, revocation state, admission counters, provider reservations and external-effect knowledge never move backward. An older binary whose write ABI is incompatible may provide a qualified read-only diagnostic/export mode, or refuse entirely. Do not automatically reverse a migration, restore a backup or start a new task ID to make old code run.

Omarchy root snapshots leave `/home` and `~/.config` unchanged. After root rollback, the older packaged binary must detect newer controller state, plugin/protocol drift and stale native dependencies before writing. A shell plugin that no longer loads must not prevent recovery through a separately packaged CLI diagnostic path. [Omarchy snapshot behavior](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/manual/47-system-snapshots.md)

Backups are explicit local operations. A consistent backup set includes controller schema/version and activation journal, operator configuration, task/original mappings, current unresolved-operation fences, native store snapshot/receipt anchor references, artifact manifests and required public trust material. Native stores use their own consistent backup API; copying a live SQLite file without its documented consistency boundary is insufficient. Include model/provider reservation state if required by the qualified adapter. Omit Unix sockets, PID locks, scratch trees, core dumps and unnecessary plaintext credentials. Record separately which secret/key restoration is required from trusted custody and which immutable runtime packages must remain available.

A backup manifest records generation, hashes, capture time/boot identity, unresolved originals, encryption method and state/native ABI. It explicitly says that local backup age cannot establish whether external effects occurred afterwards. Initial proposed retention is three explicitly created local snapshots; deletion refuses any snapshot that is the sole known recovery artifact for unresolved state. Configure another destination/retention only through operator settings, never background upload. Sensitive backups require encryption with separately recoverable keys.

Restore first stages under a fresh private destination without following archived paths/links. Verify integrity and compatibility; ignore archived sockets/locks. Reconcile against current native authority, external operation state and receipt rollback anchors before any effect. An unavailable native service or missing anchor produces `blocked_unknown` for affected tasks. Restoration of an older local ledger cannot reopen spent authority. Even if filesystem hashes match perfectly, recovery is incomplete until these semantic checks pass. The controller never signs substitute receipts.

### Diagnosis, bounded monitoring and privacy

The proposed `health.get` response reports separate dimensions: backend connectivity, supported protocol, package/signature/inventory identity, effective host enforcement, resource headroom, credential availability/expiry without values, session ownership, native connectivity/recovery and state integrity. Every observation has time, boot/session identity and freshness. Healthy service liveness alone does not mean tasks are safe to start. Errors name a stable code, affected capability, operator action and evidence reference, without exposing private paths or tokens unnecessarily.

Proposed default monitoring: local only; event-driven task updates, one host-health refresh per 30 seconds while the panel is visible, one per 5 minutes while idle, and on start/resume/configuration change. Failed connectivity backs off from 5 seconds to 5 minutes with jitter. One collector instance and one outstanding sample per source; no process enumeration, network scan or model request polling without a concrete health need. Reuse bounded subscriptions to avoid a per-widget polling storm. The support tuple sets a proposed 50 MiB controller RSS increment while idle and less than 1% of one CPU averaged over 10 minutes; measure these targets rather than claim them as delivered performance.

Operational logging defaults to structured severity/code, hashed identifiers and bounded counters. Do not record prompts, model output, source contents, secret environment, authorization headers, plaintext credentials, clipboard, window titles, screenshots or full home paths. Native receipts are retained under native policy, separately from rotatable operational logs. Journald is not an authoritative task store.

Initial proposed bounds: 8 KiB per diagnostic message, 10 messages/second with burst 50 per component, 20 MiB rotating application diagnostics and seven-day local retention. Rate limiting summarizes dropped counts. Safety/fence/receipt records are never deleted because a log budget is exhausted; stop new effects before authoritative storage capacity is lost. System journal configuration remains operator-owned; apply per-unit rate limits and minimize messages rather than rewriting global journald settings.

Diagnostic export is user-initiated and local by default. Generate a bounded manifest of support tuple, error codes, relevant redacted state and permitted counters, show contents before sharing, and refuse credentials/raw project material. A proposed 10 MiB default archive cap causes a clear partial-export marker listing omitted classes. No telemetry endpoint, crash upload, external support ticket or remote receipt export is enabled by default. Separate explicit authorization is required for any external delivery. Status/logs cannot replace signed execution receipts.

### Disable, uninstall and storage failures

Disabling QML presentation does not silently erase or orphan tasks: show the known background-work policy before the user disables it; controller lifecycle remains governed by session policy. Explicitly stopping the backend refuses new work, performs bounded stop, preserves originals and leaves recovery-readable state. Removing the backend package does not purge journals, project artifacts, native anchors, user configuration or backups.

Uninstall reports any unresolved operation and the package version/tools needed for later reconciliation, then removes only package-owned code/units and its own registered plugin entries if separately requested. It does not disable unrelated user services, delete `~/.config`, modify shell aliases or remove user projects. Purge is a separate explicit destructive operation with an inventory and preservation/export option; it refuses while unresolved effects or dependent receipt anchors remain unless a separately designed native decommission procedure settles custody. No purge tool is implied to exist today.

Storage errors are first-class states. ENOSPC/inode exhaustion before staging leaves the old generation active if complete. Signature or extraction failure leaves staging inert. EIO/torn write before activation leaves old or new valid binding, otherwise a refusal with recovery instructions. Missing old packages, incompatible state or partial host rollback keeps execution disabled until a signed compatible recovery package is installed. Never delete uncertain task state automatically to make startup succeed. Trusted activation/recovery metadata uses retained safe directory descriptors and non-following durable publication, consistent with the Linux contract.

Security update ownership belongs to packaging and Linux/native maintainers. Publish a signed advisory with affected artifact/profile identities, disabled capabilities and a qualified replacement tuple. A revoked runtime stops new admissions; already running work follows bounded stop/reconciliation policy. Critical updates do not acquire new authority or change provider/model/recipe selectors. Proposed triage target is one business day after a verified vulnerability report, with a published disposition and qualification owner; this is a proposed operational objective, not a current support promise.

## Proposed acceptance

The independent tester captures package files, signatures, source inventory and all host/profile dimensions. Existing developer checkouts or pre-existing unrecorded binaries invalidate clean-install evidence.

### AT-OPS-001: Plugin without backend

Trigger: install/load the QML plugin on a clean host with no backend, then inspect its behavior. Observable outcome: actionable unavailable state and exact dependency requirements; no download, privileged prompt, package mutation or new unit. Independent oracle: filesystem/package diff, process/network observation and absence of backend executables. Evidence artifact: `ops-001-plugin-only.json` and synthetic UI screenshot.

### AT-OPS-002: Exact scoped support tuple

Trigger: install the selected tuple, then change one of plugin, Node, native helper, runtime library, unit override, kernel or provider profile. Observable outcome: named positive profiles remain traceable; affected qualification fails without claiming unrelated dimensions failed or passed. Independent oracle: independent inventory hash/probe tool and acceptance-artifact verification. Evidence artifact: `ops-002-support-matrix.json`.

### AT-OPS-003: Reproducible clean builds

Trigger: two independent clean-chroot builds use the declared public inputs and toolchain; repeat with a deliberately changed dependency. Observable outcome: original package contents match, changed input changes identity or is rejected, and SBOM/license/provenance inventory covers delivered files. Independent oracle: independent package extraction/hash comparison and source resolution with no developer filesystem access. Evidence artifact: `ops-003-rebuild.json`, both `.BUILDINFO` files, SBOM and signed provenance.

### AT-OPS-004: Signature and trust failures

Trigger: install/activate valid artifacts, then corrupt package bytes, substitute support manifests, use an unknown/revoked key and replay a disallowed older manifest. Observable outcome: valid channel works; negatives cannot activate or disable verification. Independent oracle: independent signature verifier, pacman database and active-generation readback. Evidence artifact: `ops-004-artifact-trust.json`.

### AT-OPS-005: Host and mise drift

Trigger: place hostile `node`/`chio` shims first in PATH, run a normal mise upgrade after Omarchy's post-update hook, replace a runtime library and reboot into a changed kernel. Observable outcome: shims never execute; actual mismatched runtime/host pins block new effects until separately accepted. Independent oracle: shim canary execution count, `/proc` executable/maps identities and independent pre/post manifests. Evidence artifact: `ops-005-runtime-drift.json`.

### AT-OPS-006: Service activation and session ownership

Trigger: install without enabling, opt in, crash repeatedly, logout with lingering enabled, then log back in. Observable outcome: no automatic start on install, bounded restart rate, tasks stop on session loss and recovery starts without automatic guest replay. Independent oracle: systemd unit/job records, logind sessions and external native request counter. Evidence artifact: `ops-006-user-service.json`.

### AT-OPS-007: Effective unit hardening

Trigger: run positive controller/launcher/relay/guest workflows under their units; disable a required user-namespace/controller feature and add an incompatible hardening override. Observable outcome: positive composition works; missing protection or broken bootstrap produces precise refusal, never an unconfined retry. Independent oracle: actual kernel properties, effective cgroup files and Linux negative probes; analyzer scores are supplementary. Evidence artifact: `ops-007-unit-matrix.json` with directive and measured-effect table.

### AT-OPS-008: Crash-safe staged activation

Trigger: update a running installation and kill power/process at every durable stage, including package extraction, migration journal, activation rename and recovery start. Observable outcome: one valid generation/state binding or a safe refusal, no mixed-generation task or repeated original effect. Independent oracle: package/activation filesystem inspection and external mutation counter. Evidence artifact: `ops-008-update-fault-matrix.json` with old/new digests and recovered stage.

### AT-OPS-009: Application and root rollback ABI

Trigger: perform compatible code rollback; try incompatible write-ABI rollback; boot an older Omarchy root snapshot with newer home state and plugin. Observable outcome: compatible recovery preserves latest custody; incompatible paths are diagnostic-only/refused, no old snapshot overwrites new ledger. Independent oracle: state/native journal hashes, monotonic receipt anchor and external effect count. Evidence artifact: `ops-009-rollback.json`.

### AT-OPS-010: Independently updated plugin

Trigger: update/reload QML during a mutation and use clients above/below the supported protocol range. Observable outcome: compatible client reconnects and queries the original request; incompatible clients display bounded compatibility failure, with no duplicate controller/task/effect. Independent oracle: process/socket census and native idempotency/effect counter. Evidence artifact: `ops-010-protocol-reload.json`.

### AT-OPS-011: Bounded local monitoring

Trigger: leave panel open and closed for separate 10-minute windows, run 20 subscribing widgets, disconnect native service and corrupt one health dimension. Observable outcome: collectors/subscriptions coalesce, polling/backoff stay within defaults, failures identify the actual layer, and measured resource targets are reported. Independent oracle: external process CPU/RSS sampling and packet/IPC request counts. Evidence artifact: `ops-011-health-monitoring.json`; target misses block the selected UX acceptance until resolved or explicitly revised.

### AT-OPS-012: Diagnostic privacy and limits

Trigger: seed canaries in prompts, provider tokens, repository contents, clipboard, window titles and local paths; flood errors and request a diagnostic export above 10 MiB. Observable outcome: canaries absent, message/storage limits hold, export marks omissions, no external upload, and authoritative fences/receipts remain intact. Independent oracle: independent journal/archive content scan, network capture and state inventory. Evidence artifact: `ops-012-privacy-bounds.json` with redacted canary hashes.

### AT-OPS-013: Consistent backup

Trigger: back up idle state and active/unknown operation state, then attempt backup with missing key custody metadata and an interrupted native-store snapshot. Observable outcome: valid backups contain verifiable declared consistent state; invalid backups are incomplete/refused and never labeled recoverable. Independent oracle: independent manifest verifier and native snapshot/anchor verifier. Evidence artifact: `ops-013-backup.json` and encrypted fixture backup with separately controlled synthetic keys.

### AT-OPS-014: Restore without replay

Trigger: restore valid state, a corrupt archive, an older pre-effect backup, a symlink/path-traversal archive and state whose native authority is offline. Observable outcome: exact positive recovers; malformed content cannot escape staging; old/unknown effects remain fenced without replacement operation IDs. Independent oracle: outside sentinel files, native original ledger, anchor monotonicity and resource mutation counter. Evidence artifact: `ops-014-restore.json`.

### AT-OPS-015: Removal preserves custody

Trigger: disable plugin, stop service, uninstall backend and request purge with an unresolved operation. Observable outcome: tasks follow the stated lifecycle; package code is removed, user projects/state/anchors/backups remain, purge refuses unresolved custody and gives a recovery inventory. Independent oracle: independent before/after package/file inventory, process census and native journal. Evidence artifact: `ops-015-uninstall.json`.

### AT-OPS-016: Storage and interrupted package failures

Trigger: exhaust space/inodes, inject EIO, make state read-only, remove cached recovery package and interrupt a package upgrade before/after activation. Observable outcome: old valid runtime persists where available; otherwise execution stays disabled with specific recovery steps, no silent journal reset or cleanup of unknown tasks. Independent oracle: fault harness, generation/state hashes and external effect counter. Evidence artifact: `ops-016-storage-recovery.json`.

### AT-OPS-017: Revocation and security update

Trigger: publish a test signed advisory revoking the active fixture runtime, attempt an unsigned replacement and then activate the qualified successor. Observable outcome: new admissions stop for affected profiles, bounded stop/recovery preserves originals, unsigned replacement fails, successor does not auto-resume or expand authority. Independent oracle: signature verifier, native authority comparison and observed request/effect counts. Evidence artifact: `ops-017-security-update.json` plus simulated triage/owner record.

### AT-OPS-018: Independent clean consumer cycle

Trigger: a tester other than the implementer starts from the exact clean x86_64 Omarchy image with no local development files and performs install, named-profile task, update, rollback, backup, restore and uninstall using only public signed artifacts/docs. Observable outcome: all scoped positive and negative cases pass; unavailable native/provider/approval/delegation profiles are excluded explicitly rather than implied qualified. Independent oracle: independently recorded host/package/source identities, external resource effects and native receipt verification. Evidence artifact: `arch-install-upgrade-recovery` with reproducible runbook, raw artifacts and reviewer sign-off. This proposed release case remains unexecuted.

## Risks and prerequisite owners

Packaging owns final package/repository/key design, reproducibility and an offline-compatible recovery path. Native Chio owns state migration, receipt-anchor and unresolved-operation semantics. Linux security owns per-unit effective protection and runtime composition. Desktop integration owns actual user-session activation and protocol mismatch UX. Operations owns retention, signed advisories and recovery documentation. Source research cannot close these delivery gates; public release requires the named independent acceptance artifacts.
