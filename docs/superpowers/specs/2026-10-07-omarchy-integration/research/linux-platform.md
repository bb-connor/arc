# Linux platform and distribution research

Status: Proposed research baseline, inspected 2026-10-07.

Confidence: high in the distinctions below because they follow inspected implementation and upstream manuals; moderate in the proposed Omarchy deployment because no clean x86_64 Omarchy runtime was exercised during this research. This is source research, not confinement, install, update or release qualification.

Scope: Linux enforcement, lifecycle and Arch packaging. The current platform contract is the [Omarchy annex](../ANNEX.md), under the [shared desktop program](../../2026-10-07-desktop-integration/README.md). The numbered platform contracts were retired. Retained source observations below remain research evidence, not installed qualification.

Consolidation decision (2026-10-07): isolation denies and Chio grants. Reuse the restricted Pi bubblewrap profile and Docker-based `chio-mini-swe` through thin S7 evidence adapters, with `chio-process` custody and `chio-secure-ipc` peer authentication. Extend those owners instead of building an Omarchy runner, sandbox or peer-auth stack. The workbench is the first client of one shared C-layer controller outside the TCB. The cage observations below constrain its tool-server profile; they do not propose using it for Node/Pi. Delegation belongs to kernel/work/process owners and remains deferred for this desktop delivery.

## Findings that change the design

1. Chio can provide a governed execution backbone without making the desktop controller another authority. The QML plugin and controller are trusted desktop-user software. Agent guests, test recipes and protected resources require separately identified enforcement boundaries. A socket under an owner-only directory does not protect the user from malicious code already running as that user.
2. A successful Pi bubblewrap test does not qualify the stricter native cage or an Omarchy installation. Conversely, a small native cage probe does not qualify Node, Pi, arbitrary project tests, a dynamic loader inventory or a provider call. Each composition requires its own positive and negative acceptance.
3. Installing a QML Git plugin cannot install the Rust controller, Chio native components, pinned Node runtime or user units. Omarchy's installer clones and validates plugin files without an install hook or sudo. Separate packaging and protocol compatibility are required. [Omarchy plugin manual](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/manual/32-shell-plugins.md)
4. Omarchy's `post-update` hook runs before `omarchy-update-mise`, which invokes `mise up`. That hook cannot certify the final runtime dependency tuple. Chio must remeasure on start and admission, and use package-owned absolute runtime paths. [Update implementation](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-update), [mise update implementation](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-update-mise)
5. A root snapshot restores neither `/home` nor `~/.config`. A root rollback can therefore restore an older binary while retaining newer user state and QML. Runtime and state compatibility must be checked after rollback; snapshot success is not Chio recovery success. [Omarchy snapshot manual](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/manual/47-system-snapshots.md)

## Inspected Chio evidence and prerequisite artifacts

Public source identity is distinct from package availability. The Pi candidate below was reachable during this research; no install or release claim follows from that observation.

| Source map identifier | Material inspected | Supported conclusion | Remaining prerequisite |
|---|---|---|---|
| `LINUX-PI-CANDIDATE` | Public Pi candidate `4214a5a8ddec776a5ff9ec78007442683fd8df03`, `docs/RUN-LIMITS-LINUX.md`, source launcher/filter and coding-resource documentation | Whole-guest architecture separates fixed gateway/model relays from credentials, operator state and protected source; distinct test-recipe confinement exists | Run the packaged candidate and actual provider/resource stack on x86_64 Omarchy |
| `LINUX-PI-DEVELOPMENT-INSPECTION` | Current development worktree's `src/linux-sandbox.ts`, `src/protected-cli.ts`, `src/coding-resource/recipe-sandbox.ts`, `docs/NATIVE-PREREQUISITES.md` | Runtime hashes and mount closure are checked; resumed profile validation precedes parent publication; approval decision is refused; Node thread-compatible BPF differs from strict cage | Retained-path publication audit, service composition and exact x86_64 real-syscall acceptance |
| `LINUX-NATIVE-CAGE-INSPECTION` | Newer native implementation's `crates/security/chio-cage/README.md`, launch implementation, `third_party/provenance/linux-enforcement-stack.toml`, platform doctor | Source requires x86_64, Linux at least 6.7, Landlock ABI at least 4, seccomp, retained descriptors, pidfds, parent-child ptrace exec observation and no partial enforcement | Publicly available exact source/runtime inventory, native qualification artifact and protected resource composition on selected Omarchy host |
| `LINUX-MAIN-INVENTORY` | Specification checkout inventory on 2026-10-07 | The newer `crates/security/chio-cage` and reference-process files are absent from this checkout | Integration/release owner must provide source-qualified prerequisite artifacts; these documents must not link nonexistent local paths as implemented features |

The Pi candidate's Linux runtime document exactly matched the inspected development document (SHA-256 `3f23980b031c1385ba3c0eebdffaf22fca4e5d0b272b2f7fe076046eddd69904`). Its recorded measurement was ARM64 Linux 6.8.0-64-generic, Node 22.23.1, bubblewrap 0.8.0-2+deb12u1 and pinned Debian libraries, inside a privileged outer container with networking disabled. It expressly leaves real x64, ordinary container defaults, native coding/P5 and provider qualification open. This is historical evidence stated by that artifact, not a new test performed here. [Pinned Pi evidence](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/RUN-LIMITS-LINUX.md)

The native cage source binds a verified manifest registry and runtime topology to a retained-descriptor launch plan. A signed manifest alone is insufficient. Filesystem and network Landlock must both report full enforcement, and a separate seccomp filter is installed. The source prohibits socket creation and process creation; brokered communication uses a preconnected descriptor. It supports a specifically inventoried dynamic ELF target, which does not establish that an arbitrary dynamic language runtime fits its syscall and resource model. Its README explicitly says namespaces and cgroups are outside that crate. These are `LINUX-NATIVE-CAGE-INSPECTION` conclusions, pending a distributable prerequisite artifact.

One Pi documentation/source detail needs explicit qualification: the prose describes the bubblewrap reaper's filter relationship differently from a version-specific source comment. The implementation gate must observe the actual launcher/reaper/guest process tree and effective filters. A comment or CLI option list is not the oracle for reaper behavior.

## Upstream Linux conclusions

| Identifier | Primary reference | Finding and design consequence |
|---|---|---|
| `LINUX-LANDLOCK` | [Kernel Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html) | Query the actual ABI and handled rights. Kernel version alone does not establish active LSM enforcement. Chio's required profile must reject missing rights or partial enforcement, even though general upstream examples can degrade gracefully. Apply a required policy before guest threads exist or qualify synchronization explicitly. |
| `LINUX-SECCOMP` | [Kernel seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html) | Filter construction is architecture-sensitive and seccomp is one component of confinement. Test native and alternate syscall paths, including x32 on x86_64; a syscall denial list does not identify allowed network destinations or filesystem objects. |
| `LINUX-BWRAP` | [bubblewrap v0.11.0 README](https://github.com/containers/bubblewrap/blob/v0.11.0/README.md), [v0.11.0 manual source](https://github.com/containers/bubblewrap/blob/v0.11.0/bwrap.xml) | Bubblewrap constructs namespaces but the caller chooses the security policy. New-session/terminal separation, descriptor inheritance, mount closure and exposed sockets matter. A non-setuid build with working unprivileged user namespaces is the proposed first package profile; no privileged fallback. The documentation version is a research pin, not the selected shipping version. |
| `LINUX-CGROUP` | [Kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html) | Descendants inherit membership; cgroup population and controller counters provide independent process/resource observations. Controller availability and delegation must be measured. Cgroups supplement confinement and do not turn a trusted same-user controller into an isolation boundary. |
| `LINUX-PATH` | [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html), [rename](https://man7.org/linux/man-pages/man2/renameat2.2.html), [fsync](https://man7.org/linux/man-pages/man2/fsync.2.html) | Retain directory descriptors and constrain traversal. Atomic namespace replacement and crash durability are separate properties; sync the file and containing directory. Existence checks followed by ordinary pathname writes are not a race-resistant publication protocol. |
| `LINUX-CLOCK` | [clock_gettime](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) | `CLOCK_BOOTTIME` includes suspend, while `CLOCK_MONOTONIC` excludes it. Realtime can jump. Bound local task lifetime by a boot-associated boottime deadline; retain authority-issued absolute expiry and reconcile after restart or clock uncertainty. |

## systemd conclusions

The official hosted HTML returned HTTP 403 during this research. The versioned upstream manual source was fetched instead; v258 is a documentation pin, not a claim about Omarchy's installed systemd version.

| Identifier | Primary reference | Finding and design consequence |
|---|---|---|
| `LINUX-SD-EXEC` | [systemd v258 execution manual](https://github.com/systemd/systemd/blob/v258/man/systemd.exec.xml) | Some sandbox directives are unavailable or degrade in user managers without underlying features; filesystem namespacing commonly needs `PrivateUsers`. Read-only path protections do not prohibit connecting to Unix sockets under those paths. Test observed behavior and namespace support, not just `systemd-analyze security` scores. |
| `LINUX-SD-KILL` | [systemd v258 kill manual](https://github.com/systemd/systemd/blob/v258/man/systemd.kill.xml) | Control-group killing covers remaining members; the manager uses a graceful signal followed by a final signal after its stop timeout. The product must still verify absence and reconcile effects. |
| `LINUX-SD-RESOURCE` | [systemd v258 resource manual](https://github.com/systemd/systemd/blob/v258/man/systemd.resource-control.xml) | Resource limits depend on the active hierarchy/controllers and inherited user-manager limits. Measure effective values under the service. `TasksMax` also constrains threads, which matters for Node. |
| `LINUX-SD-SESSION` | [systemd v258 special targets](https://github.com/systemd/systemd/blob/v258/man/systemd.special.xml), [logind API](https://github.com/systemd/systemd/blob/v258/man/org.freedesktop.login1.xml) | Graphical-session target coupling and logind sleep/shutdown notifications are useful lifecycle inputs. Prove actual Omarchy target activation and lock notification wiring, including user lingering and missed-event reconnects. A locked-hint property is not proof against a malicious trusted shell. |

A controller-wide rule that forbids user namespaces can accidentally prevent the legitimate bubblewrap launcher. Conversely, blindly enabling every hardening option can break cage ptrace handshakes, retained procfs identity checks or JIT-based workers. The design therefore separates controller, trusted launch/relay components and guest units, with a per-unit tested directive matrix. No exception for one role broadens another role.

## Arch packaging conclusions

- A reproducible package needs fixed source archives/commits, verified source checksums, a recorded build environment and deterministic output. Package metadata supports architecture, dependencies, source hashes and signatures; a VCS moving branch alone does not establish an exact runtime. [PKGBUILD manual](https://man.archlinux.org/man/PKGBUILD.5.en)
- Clean-chroot builds isolate build dependencies; `.BUILDINFO` captures the build environment. Two independently built packages must still be compared before claiming reproducibility. [makechrootpkg manual](https://man.archlinux.org/man/makechrootpkg.1.en), [BUILDINFO manual](https://man.archlinux.org/man/BUILDINFO.5.en)
- Package/repository signature verification identifies accepted publishers and integrity, not runtime compatibility or complete security. Keep signature checking required, distribute key identity through an explicit trust process, and reject untrusted/revoked artifacts. [pacman configuration](https://man.archlinux.org/man/pacman.conf.5.en)

Arch is a moving host environment. The proposed support tuple binds the exact Omarchy revision, system packages, kernel/LSM probes, user-service configuration, runtime inventory, protocol and state ABI. Ordinary system upgrades are not blocked by Chio; unsupported tuples stop new Chio mutations until qualification succeeds. Using `mise` shims or user's `PATH` for the protected runtime would silently change that tuple and is rejected.

## Decision and alternatives

Select a thin native QML plugin over the shared Rust controller and browser workbench, with separate pacman delivery and explicit Chio dependencies. Qualify one x86_64 Omarchy/Pi sealed W1 work composition first, reusing mini-swe/restricted Pi/resource owners. Retain their runtime inventories for the Pi guest and each protected resource. Do not force Node into the strict native cage or relax that cage's policy to make a demo start.

Preserve bounded hostile-descendant cleanup as an acceptance gate in shared Linux qualification tooling. A dedicated fixture worker verifies child-subreaper custody before launch, remains alive while reaping within bounded deadlines and reports unavailable custody explicitly. Exercise double-fork, process-group escape, detached descendants, full pipes and timeout escalation. Independent census/cgroup observations must prove absence; a timeout return or worker exit is insufficient. This is a harness requirement, not a new Omarchy process runner or a change to controller subreaper state.

A single unsandboxed desktop process would have the smallest package surface but cannot enforce the chosen guest boundary. A privileged system daemon could protect against a stronger local adversary but adds root and account-boundary complexity beyond the first threat profile. A universal container image simplifies dependency capture yet does not prove access to actual Omarchy lifecycle/compositor interfaces or ordinary user-namespace support. A plugin-managed download script bypasses the plugin model and creates an unreviewed updater.

## Research risks and owners

| Prerequisite owner | Artifact required before runtime work can claim completion |
|---|---|
| Linux security owner | `omarchy-x86_64-enforcement-qualification`: actual guest, recipe and protected-resource positives/negatives, observed kernel state, independent mutation counters, descendant cleanup |
| Native Chio owner | `native-resource-compatibility`: public exact source and binary identities, signed manifest topology, supported resource launcher, authority and recovery acceptance |
| Pi owner | `pi-omarchy-runtime-manifest`: exact Node/interpreter/shared-library/runtime closure, provider route profile, privilege-free launcher/reaper tests |
| Desktop lifecycle owner | `omarchy-session-lifecycle`: real lock/logout/suspend/resume/session target wiring with missed-event and lingering cases |
| Packaging owner | `arch-install-upgrade-recovery`: signed reproducible package tuple, state migration/rollback rules, clean consumer install and root-snapshot rollback tests |

All five are open. Writing or reviewing these specifications closes none of them.
